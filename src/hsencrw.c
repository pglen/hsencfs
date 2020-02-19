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

// Shorthands to make code compacter. Notice: { block enclosed }

#define EVAL_MEM_GO(memmsg, enddx)                                      \
         { if (loglevel > 0)                                            \
                syslog(LOG_DEBUG, "Cannot get %s memory.\n", memmsg);   \
            res = -ENOMEM;                                              \
            goto enddx; }

#define EVAL_READ_GO(msgm, xlen, enddx)                                 \
          { if (loglevel > 0)                                           \
                syslog(LOG_DEBUG, "Cannot read %s, len=%d\n",           \
                                msgm, xlen);                            \
            res = -errno;                                               \
            goto enddx; }

// -----------------------------------------------------------------------
// Intercept write. Make it block size even, so encryption / decryption
// is symmetric. Below, help with variable names.
//
//    |                     total             |
//    new_beg (buf % n)                       new_end (buf % n) * n + (buf % n ? n : 0)
//    |   .   .   .   .   .   .   .   .   .   |
// ===-------|--------------|---------------------============
//           ^ offs         ^offs + size    | - lastbuff - |
//    | skip |    opend    |
//

static int xmp_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)

{
	int res = 0, loop = 0;
    if(size == 0) {
        if (loglevel > 3)
            syslog(LOG_DEBUG, "zero write on '%s'\n", path);
        return 0;
        }

    if (loglevel > 3)
        syslog(LOG_DEBUG,
                " *** xmp_write(): name '%s'\n", path);

    // Change file handle to reflect read / write
    //int ret3 = fchmod(fi->fh, S_IRUSR | S_IWUSR |  S_IRGRP);
    //if (retls3 < 0)
    //    if (loglevel > 0)
    //    syslog(LOG_DEBUG,
    //            " Cannot change mode on write '%s'\n", path);

    // Save current file parameters, as the FS sees it
    //off_t oldoff = lseek(fi->fh, 0, SEEK_SET);
    off_t fsize = get_fsize(fi->fh);

    // ----- Visualize what is going on ------------------------------
    // Intervals have space next to it, points touch bars
    // Intervals have no undescore in name; Note: fsize is both point
    // and interval.
    //
    //         [             total             ]
    //         |new_beg                        |new_end
    //         | skip |            |fsize      |
    // ===-----|------|------------|===============
    //         |      |offset   op_end|        |
    //                |   size        |        |
    //         |--------------|----------------|
    //         |mem           |   sideblock    |
    //         |    predat    |
    // see also visualize.txt

    // Pre-calculate stuff
    size_t op_end  = offset + size;
    size_t new_beg = (offset / HS_BLOCK) * HS_BLOCK;
    size_t new_end = (op_end / HS_BLOCK) * HS_BLOCK;
    if((op_end % HS_BLOCK) > 0)
        new_end += HS_BLOCK;

    size_t  total = new_end - new_beg;
    size_t  skip  = offset - new_beg;
    size_t  predat =  total - HS_BLOCK;

    if (loglevel > 3)
        {
        syslog(LOG_DEBUG,
            "Prep wr:  offset=%ld size=%ld fsize=%ld\n",
                                         offset, size, fsize);
        //syslog(LOG_DEBUG,
        //    "Prep wr2: new_beg=%ld total=%ld skip=%ld\n",
        //                                 new_beg, total, skip);
        //syslog(LOG_DEBUG,
        //    "Prep wr3: fsize=%ld\n", fsize);
        }

    // Scratch pad for the whole lot
    void *mem =  malloc(total);
    if (mem == NULL)
        EVAL_MEM_GO("main block", endd);

    memset(mem, 0, total);                  // Zero it

    //if (loglevel > 4)
    //    syslog(LOG_DEBUG, "File size fsize=%ld\n", fsize);

    // Do it: Read / Decrypt / Patch / Encrypt / Write

    // Close to end: Sideblock is needed
    if(new_end >= fsize)
        {
        char *bbuff = NULL;
        // Assemble buffer from pre and post
        int ret = read_sideblock(path, &bbuff, HS_BLOCK);
        if(!bbuff)
            EVAL_MEM_GO("sideblock", endd);
        if(ret && ret != HS_BLOCK)
            EVAL_READ_GO("sideblock", HS_BLOCK, endd);

        //if (loglevel > 3)
        //    syslog(LOG_DEBUG, "Got sideblock: '%s'\n",
        //                            bluepoint2_dumphex(bbuff, 8));

        // Patch in sb data
        memcpy(mem + predat, bbuff, HS_BLOCK);
        kill_buff(bbuff, HS_BLOCK);

        // Get original
        int ret3 = pread(fi->fh, mem, skip + size, new_beg);
        if (loglevel > 2)
            syslog(LOG_DEBUG,
                "Pre read: ret=%d  new_beg=%ld\n", ret3, new_beg);

        if(ret3 < 0)
            {
            if (loglevel > 0)
                syslog(LOG_DEBUG, "Cannot pre read data. ret3=%d errno=%d\n", ret, errno);
            //res = -errno;
            //goto endd;
            }
        else if(ret3 < skip + size)
            {
            if (loglevel > 0)
                syslog(LOG_DEBUG, "Pre write data. len=%ld\n", skip + size);

            // Expand file
            int ret4 = pwrite(fi->fh, mem, skip + size, new_beg);
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

    if (loglevel > 2)
        syslog(LOG_DEBUG,
            "Writing: size=%ld offs=%ld skip=%ld\n",
                                               size, offset, skip);
    // Grab the new data
    memcpy(mem + skip, buf, size);

    // Encryption / decryption by block size
    hs_encrypt(mem, total, passx, plen);

    // Write it back out, all that changed
    int res2 = pwrite(fi->fh, mem, skip + size, new_beg);
	if (res2 < 0)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on writing file: %s res %d errno %d\n", path, res, errno);

		res = -errno;
        goto endd;
        }
    res = res2 - skip;

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Written: res %d bytes\n", res);

    if(new_end >= fsize)
        {
        // Write sideblock back out
        //if (loglevel > 3)
        //    syslog(LOG_DEBUG, "Write sideblock: '%s'\n",
        //                            bluepoint2_dumphex(mem + predat, 8));

        int ret2 = write_sideblock(path, mem + predat, HS_BLOCK);
        if(ret2 < 0)
            {
            if (loglevel > 0)
                syslog(LOG_DEBUG, "Error on sideblock write %d\n", errno);

    		res = -errno;
            goto endd;
            }
        }

    // Reflect new file position
    //lseek(fi->fh, oldoff + res, SEEK_SET);
    lseek(fi->fh, offset + res, SEEK_SET);

   endd:
    // Do not leave data behind
    if (mem)
        {
        // Just to confuse the would be debugger
        if(rand() % 2 == 0)
            hs_decrypt(mem, total, "passpass", 8);

        kill_buff(mem, total);
        }
	return res;
}

// EOF



