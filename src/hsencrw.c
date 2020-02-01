// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//
// Read write 'C' include. Extracted for eazy editing. This code took forever.
//
// Here is the task:
//
//      Intercept read / write. Expand boundaries to match encryption
//      block boundaries.
//      If last block, gather data from sideblock, patch it in.
//      Decrypt / Encrypt.
//      Patch required data back.
//

// -----------------------------------------------------------------------
// Intercept write. Make it block size even, so encryption / decryption
// is symmetric. Below, help with variable names.
//
//    |                     total             |
//    new_beg (buf % n)                       new_end (buf % n) * n + (buf % n ? n : 0)
//    |   .   .   .   .   .   .   .   .   .   |
// ===-------|--------------|---------------------============
//           ^ offs         ^offs + size    | - lastbuff - |
//    | skip |    opsize    |
//

static int xmp_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int res = 0, loop = 0;
    if(size == 0) {  // Nothing to do
        goto endd;
        }
     // Save current file parameters
    off_t oldoff = lseek(fi->fh, 0, SEEK_SET);
    off_t fsize = get_fsize(fi->fh);

    // Pre-calculate stuff
    size_t new_beg = (offset / HS_BLOCK) * HS_BLOCK;
    size_t opsize  = offset + size;
    size_t new_end = (opsize / HS_BLOCK) * HS_BLOCK;
    if((opsize % HS_BLOCK) > 0)
        {
        new_end += HS_BLOCK;
        }

    //if(new_end > fsize)
    //    {
    //    new_end =  (fsize / HS_BLOCK) * HS_BLOCK;
    //    }

    size_t total = new_end - new_beg;
    off_t  skip  = offset - new_beg;
    if (loglevel > 3)
        syslog(LOG_DEBUG,
                "About to write: '%s' offset=%ld size=%ld new_beg=%ld total=%ld\n",
                                         path, offset, size, new_beg, total);
    // Scratch pad for the whole lot
    void *mem =  malloc(total);
    if (mem == NULL)
        {
     	if (loglevel > 2)
            {
            syslog(LOG_DEBUG, "Cannot allocate memory %ld", total);
            }
        res = -ENOMEM;
        goto endd;
        }

    memset(mem, 0, total);              // Zero it

    if (loglevel > 3)
        syslog(LOG_DEBUG, "File size from stat %ld\n", fsize);

    // Read / Decrypt / Patch / Encrypt / Write

    //if(new_beg + total > fsize)
    if(new_end > fsize)
        {
        // Assemble buffer from pre and post
        char *bbuff = NULL;
        int ret = read_sideblock(path, &bbuff, HS_BLOCK);
        if(!bbuff)
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Cannot get sideblock.\n");
            res = 0;
            goto endd;
            }
        // Assemble
        off_t slack = fsize - new_beg;
        res = pread(fi->fh, mem, slack, new_beg);
        memcpy(mem + slack, bbuff,  HS_BLOCK);
        free(bbuff);
        }
    else
        {
        if (loglevel > 3)
            syslog(LOG_DEBUG,
            "About to pre read: '%s' new_beg=%ld fsize=%ld total=%ld\n",
                                        path, new_beg, fsize, total);

        res = pread(fi->fh, mem, total, new_beg);

    	if (res == -1)
            {
            // We throw this away, as the buffer is zeroed out
            if (loglevel > 3)
                syslog(LOG_DEBUG,
                    "Write: Cannot pre read for encryption %s size=%ld total=%ld offs=%ld\n",
                                   path, size, total, offset);
            errno = 0;
            res = 0;
            goto endd;
            }
        if (res < total)
            {
            if (loglevel > 3)
                syslog(LOG_DEBUG,
                    "Write: Short pre-read  %s size=%ld total=%ld offs=%ld\n",
                                   path, size, total, offset);
            }
        }

    // Buffer now in, complete
    hs_decrypt(mem, total, passx, plen);
    lseek(fi->fh, oldoff, SEEK_SET);

    if (loglevel > 2)
        syslog(LOG_DEBUG,
            "Writing file: %s size=%ld offs=%ld skip=%ld total=%ld\n",
                                              path, size, offset, skip, total);
    // Grab new data
    memcpy(mem + skip, buf, size);

    // Encryption / decryption by block size.
    hs_encrypt(mem, total, passx, plen);

    // Write it back out
    res = pwrite(fi->fh, mem + skip, size, offset);
	if (res == -1)
        {
        syslog(LOG_DEBUG, "Error on writing file: %s res %d errno %d\n", path, res, errno);
		res = -errno;
        goto endd;
        }

    // Reflect new file position
    lseek(fi->fh, oldoff + size, SEEK_SET);

    if(new_end >= fsize)
        {
        // Write sideblock back out
        int ret2 = write_sideblock(path, mem + fsize - HS_BLOCK, HS_BLOCK);
        if(ret2 < 0)
            {
            syslog(LOG_DEBUG, "Error on sideblock name %d\n", errno);
    		res = -errno;
            goto endd;
            }
        }

    if (loglevel > 3)
        syslog(LOG_DEBUG, "Written out file: %s res %d\n", path, res);

   endd:
           ;

    // Do not leave data behind
    if (mem)
        {
        // Crypt it: This is a fake encryption of the dangling memory.
        // Just to confuse the debugger
        if(rand() % 2 == 0)
            hs_decrypt(mem, total, "passpass", 8);
        else
            memset(mem, 0, total);        // Zero it
        free(mem);
        }
	return res;
}
















