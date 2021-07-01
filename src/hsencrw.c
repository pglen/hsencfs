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
// Intercept write. Make it block size even, so encryption / decryption
// is symmetric. Below, help with variable names.
//
//    |                     total             |
//    new_beg (buf % n)                       new_end (buf % n) * n + (buf % n ? n : 0)
//    |   .   .   .   .   .   .   .   .   .   |
// ===-------|--------------|---------------------============
//           ^ offs         ^offs + wsize    | - lastbuff - |
//    | skip |    opend    |
//

static int xmp_write(const char *path, const char *buf, size_t wsize, // )
                        off_t offset,  struct fuse_file_info *fi)
{
	int res = 0, loop = 0;
    if(wsize == 0) {
        if (loglevel > 1)
            syslog(LOG_DEBUG, "zero write on '%s'\n", path);
        return 0;
        }

    if (loglevel > 3)
        syslog(LOG_DEBUG,
                " *** xmp_write():fh=%ld  name '%s' wsize=%lu offs=%lu\n",
                                                fi->fh, path, wsize, offset);

    // This is a test case for evaluating the FUSE side of the system
    #ifdef BYPASS
    int res2a = pwrite(fi->fh, buf, wsize, offset);
	if (res2a < 0)
        {
        return -errno;
        }
    else
        {
        return res2a;
        }
    #endif

    // Change file handle to reflect read / write
    //int ret3 = fchmod(fi->fh, S_IRUSR | S_IWUSR |  S_IRGRP);
    //if (retls3 < 0)
    //    if (loglevel > 0)
    //    syslog(LOG_DEBUG,
    //            " Cannot change mode on write '%s'\n", path);

    // Save current file parameters, as the FS sees it
    //off_t oldoff = lseek(fi->fh, 0, SEEK_CUR);
    off_t fsize = get_fsize(fi->fh);

    //if (loglevel > 4)
    //    syslog(LOG_DEBUG, "File size fsize=%ld\n", fsize);

    // ----- Visualize what is going on ------------------------------
    // Intervals have space next to it, points touch bars
    // Intervals have no undescore in name;
    // Note: fsize is both point and interval.
    //         [             total             ]
    //         |new_beg                        |new_end
    //         | skip |            |fsize      |
    // ===-----|------|------------|===============
    //         |      |offset   op_end|        |
    //                |   wsize       |        |
    //         |--------------|----------------|
    //         |mem           |   sideblock    |
    //         |    predat    |
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

    if (loglevel > 3)
        {
        syslog(LOG_DEBUG,
            "Prep wr: offs=%ld wsize=%ld fsize=%ld\n",
                                         offset, wsize, fsize);
        }
    // Scratch pad for the whole lot
    void *mem =  malloc(total);
    if (mem == NULL)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Cannot get main block memory.\n");
        res = -ENOMEM;
        goto endd;
        }
     memset(mem, 0, total);                  // Zero it

    // Do it: Read / Decrypt / Patch / Encrypt / Write
    sideblock *psb = malloc(sizeof(sideblock));
    if(psb == NULL)
        {
        if (loglevel > 0)
           syslog(LOG_DEBUG, "Cannot allocate memory for sideblock '%s'\n", path);
        res = -ENOMEM;
        goto endd;
        }
    memset(psb, '\0', sizeof(sideblock));
    psb->magic =  HSENCFS_MAGIC;

    // Read in last block from lastblock file
    // Op past file end?
    if(new_end >= fsize)
        {
        size_t padd = new_end - fsize;
        // Long past?
        if(padd > HS_BLOCK)
            {
            if (loglevel > 3)
                {
                syslog(LOG_DEBUG,
                    "=== Long past EOF: %s offset=%ld size=%ld fsize=%ld new_end=%ld\n",
                                                 path, offset, wsize, fsize, new_end);
                }

            #if 0
            // Zero pad it to new end
            char *pmem = malloc(padd + 1);
            if(pmem == NULL)
                {
                if (loglevel > 0)
                   syslog(LOG_DEBUG, "Cannot allocate memory for padding '%s'\n", path);
                res = -ENOMEM;
                goto endd;
                }
            memset(pmem, '\0', padd);
            int res3 = pwrite(fi->fh, pmem, padd, fsize);
            free(pmem);
            #endif
            }

        else
            {
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
            // Patch in sb data
            memcpy(mem, psb->buff, HS_BLOCK);
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

            // New ending ... kill sideblock
            //create_sideblock(path);

            //res = -errno;
            //goto endd;
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
        int ret4 = pread(fi->fh, mem, total, new_beg);

        if (loglevel > 2)
            syslog(LOG_DEBUG,
                "Read full block: ret4=%d new_beg=%ld\n", ret4, new_beg);
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
        if (loglevel > 3)
            syslog(LOG_DEBUG,
                        "Write sideblock: new_beg=%ld predat=%ld total=%ld\n",
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
    //lseek(fi->fh, offset + res, SEEK_SET);

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
