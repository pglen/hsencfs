// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//
// Read write 'C' include. Extracted for eazy editing. This code took forever.
//
// Here is the task:
//
//      Intercept  write. Expand boundaries to match encryption
//      block boundaries.
//      If last block, gather data from sideblock, patch it in.
//      Decrypt / Encrypt.
//      Patch required data back.
//

// This is to debug the FUSE subsystem without the encryption

//#define BYPASS

// -----------------------------------------------------------------------
// Intercept write. Make it block size aligned, both beginning and end.
// This way encryption / decryption is symmetric.
//

static int xmp_write(const char *path, const char *buf, size_t wsize, // )
                        off_t offset,  struct fuse_file_info *fi)
{
	int res = 0, loop = 0;
    if(wsize == 0) {
            hslog(1, "zero write on '%s'\n", path);
        return 0;
        }
    hslog(LOG_DEBUG, "xmp_write():fh=%ld wsize=%lu offs=%lu\n",
                                fi->fh, wsize, offset);

    // This is a test case for evaluating the FUSE side of the system (is OK)
    #ifdef BYPASS
        int res2a = pwrite(fi->fh, buf, wsize, offset);
    	if (res2a < 0) {
            return -errno; }
        else {
            return res2a;  }
    #endif

    // Change file handle to reflect read / write
    //int ret3 = fchmod(fi->fh, S_IRUSR | S_IWUSR |  S_IRGRP);
    //if (retls3 < 0)
    //    if (loglevel > 0)
    //    syslog(LOG_DEBUG,
    //            " Cannot change mode on write '%s'\n", path);

    // Save current file parameters, as the FS sees it
    off_t oldoff = lseek(fi->fh, 0, SEEK_CUR);
    off_t fsize = get_fsize(fi->fh);
    hslog(4, "File fh=%d fsize=%ld\n", fi->fh, fsize);

    // ----- Visualize what is going on ----------------------
    // Intervals have space next to it, points touch bars
    // Intervals have no undescore in name;
    // Note: fsize is both point and interval.
    //
    //         [             total              ]
    //         |new_beg                         |new_end
    //         | skip  |            |fsize      |
    // ===-----|-------|------------|===============
    //         |       |offset   op_end|        |
    //                 |   wsize       |        |
    //         |---------------|----------------|
    //         |mem            |   sideblock    |
    //         |     predat    |                |
    // ------ Special case1: fsize is before offset
    //  |fsize |       |offset   op_end|        |
    //                 |   wsize       |        |
    //         |new_beg                         |new_end
    // ------ Special case2: fsize is before op_end
    //         |       |offset | op_end|        |
    //                         |fsize           |
    //         |new_beg                         |new_end
    //
    // See also visualize.txt

    // Pre-calculate stuff
    size_t op_end  = offset + wsize;
    size_t new_beg = (offset / HS_BLOCK) * HS_BLOCK;
    size_t new_end = (op_end / HS_BLOCK) * HS_BLOCK;
    if((op_end % HS_BLOCK) > 0)
        new_end += HS_BLOCK;

    size_t  total  = new_end - new_beg;
    size_t  skip   = offset - new_beg;
    size_t  predat = total - HS_BLOCK;

    hslog(3, "Write: offs=%ld wsize=%ld fsize=%ld\n", offset, wsize, fsize);

    void *mem =  hsalloc(total);
    // Was a seek past EOF?
    if(offset > fsize)
        {
        int mlen = (offset - fsize) + wsize;
        hslog(3, "Past EOF offs=%ld fsize=%ld mlen=%lld\n",
                                                     offset, fsize, mlen);
        // Fill it up, bound to bound
        void *memb =  hsalloc(mlen);
        if (memb == NULL)
            {
            hslog(0, "Cannot get fill block memory at %s\n", path);
            res = -ENOMEM; goto endd;
            }
        hs_encrypt(memb, mlen, passx, plen);
        // Write it out
        int res2 = pwrite(fi->fh, memb, mlen, fsize);
        kill_buff(memb, mlen);
        }
    else if (offset + wsize > fsize)
        {
        int mlen = (offset - fsize) + wsize;
        hslog(3, "Past EOF offs=%ld fsize=%ld mlen=%lld\n",
                                                     offset, fsize, mlen);
        }

    //else
    //    {
    //    // Scratch pad for the whole lot
    //    void *mem =  hsalloc(total);
    //    if (mem == NULL)
    //        {
    //        hslog(0, "Cannot get main block memory at %s\n", path);
    //        res = -ENOMEM; goto endd;
    //        }
    //    }

    // Do it: Read / Decrypt / Patch / Encrypt / Write
    sideblock *psb = alloc_sideblock();
    if(psb == NULL)
        {
        res = -ENOMEM;  goto endd;
        }
    int ret4 = pread(fi->fh, mem, total, new_beg);
    hslog(2, "Read full block: ret4=%d new_beg=%ld\n", ret4, new_beg);

    // Read in last block from lastblock file
    // Op past file end?
    if(new_end >= fsize)
        {
        size_t padd = new_end - fsize;
        // Long past?
        if(padd > HS_BLOCK)
            {
            // Discard far away sideblock
            hslog(3, "=== Long past EOF: %s padd=%ld\n", path, padd);
            // Insert an intermidiary op by padding it as the OS would
            }
        else
            {
            hslog(3, "=== Past EOF: %s padd=%ld\n", path, padd);
            // Close to end: Sideblock is needed
            int ret = read_sideblock(path, psb);
            if(ret < 0)
                {
                if (loglevel > 2)
                    syslog(LOG_DEBUG, "Cannot read sideblock data.\n");
                // Still could be good, buffer is all zeros
                }
            //hs_encrypt(mem, HS_BLOCK, passx, plen);
            // Assemble buffer from pre and post
            //if (loglevel > 3)
            //    syslog(LOG_DEBUG, "Got sideblock: '%s'\n",
            //                            bluepoint2_dumphex(bbuff, 8));
            // Patch in sideblock
            //memcpy(mem + predat, psb->buff, HS_BLOCK);
            //kill_buff(psb, sizeof(sideblock));
            }
        // Get original
        int ret3 = pread(fi->fh, mem + skip, wsize, new_beg + skip);
        if (loglevel > 2)
            syslog(LOG_DEBUG,
                "Pre read: ret=%d  new_beg=%ld\n", ret3, new_beg);
        if(ret3 < 0)
            {
            if (loglevel > 9)
                syslog(LOG_DEBUG, "Cannot pre read data. ret3=%d errno=%d\n", ret3, errno);
            }
        else if(ret3 < skip + wsize)
            {
            if (loglevel > 9)
                syslog(LOG_DEBUG, "Pre write data. ret=%d len=%ld\n", ret3, skip + wsize);

            // Expand file
            //int ret4 = pwrite(fi->fh, mem, skip + wsize, new_beg);
            }
        }
    else
        {
        //int ret4 = pread(fi->fh, mem, total, new_beg);
        //if (loglevel > 2)
        //    syslog(LOG_DEBUG,
        //        "Read full block: ret4=%d new_beg=%ld\n", ret4, new_beg);
        }

    // Buffer now in, complete; decrypt it
    hs_decrypt(mem, total, passx, plen);

    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "decrypt len=%ld '%s'",  total,
    //                            bluepoint2_dumphex(mem, 16));
    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "decrypt end '%s'",
    //                bluepoint2_dumphex(mem + HS_BLOCK - 16, 16));

    if (loglevel > 2)
        syslog(LOG_DEBUG,
            "Writing: wsize=%ld offs=%ld skip=%ld\n",
                                            wsize, offset, skip);
    // Grab the new data
    memcpy(mem + skip, buf, wsize);

    // Encryption / decryption by block size
    hs_encrypt(mem, total, passx, plen);

    // Write it back out, all that changed
    int res2 = pwrite(fi->fh, mem, wsize + skip, new_beg);
	if (res2 < 0)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on writing file: %s res %d errno %d\n", path, res, errno);
		res = -errno;
        goto endd;
        }
    res = res2 - skip;

    if (loglevel > 9)
        syslog(LOG_DEBUG, "Written: res %d bytes\n", res);

    if(new_end > fsize)
        {
        // Write sideblock back out
        hslog(9, "Write sideblock: new_beg=%ld predat=%ld total=%ld\n",
                                                      new_beg, predat, total);
        if (loglevel > 9)
            syslog(LOG_DEBUG, "Sideblock: '%s'\n",
                                            bluepoint2_dumphex(mem + predat, 8));

        memcpy(psb->buff, mem + predat, HS_BLOCK);
        int ret2 = write_sideblock(path, psb);
        if(ret2 < 0)
            {
            if (loglevel > 0)
                syslog(LOG_DEBUG, "Error on sideblock write %d\n", errno);

    		res = -errno;
            goto endd;
            }
        }

    // Reflect new file position
    lseek(fi->fh, offset + res, SEEK_SET);

   endd:
    // Do not leave data behind
    if (mem)
        {
        kill_buff(mem, total);
        }
    if(psb)
        {
        kill_buff(psb, sizeof(sideblock));
        }
	return res;
}

// EOF
