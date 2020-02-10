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
// Intercept read. Make it block size, (HS_BLOCK) so encryption / decryption
// is symmetric.
//
// Exception is taken when dealing with the last block. The sideblock file
// contains a copy of the last block, one that overflows the real file length.
//
// This is done to complete the last buffer for encryption.
//               |         size        |
// ===-----------|---------------------|--------------=======
//     |  skip   ^ offset              ^offset + size
//     ^ new_offset (buf % n)                              | total (buf % n + n)
//     |                               | infile
//     |                                        ^ new_end
//                                    sideblock |----------|

static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)

{
	int res = 0;
    //size_t infile = fsize - new_offset;

    if (loglevel > 3)
        {
        syslog(LOG_DEBUG,
            "xmp_read(): '%s' size=%ld offs=%ld\n", path, size, offset);
        }

    // Remember old place, get size
    off_t fsize = get_fsize(fi->fh);  off_t oldoff = lseek(fi->fh, 0, SEEK_SET);

    // Pre-calc all parameters
    size_t new_offset = (offset / HS_BLOCK) * HS_BLOCK;
    size_t skip = offset - new_offset;
    size_t getting = size + skip;
    size_t total = (getting / HS_BLOCK) * HS_BLOCK;
    if((getting % HS_BLOCK) != 0)     // Expand with one full block
        {
        total += HS_BLOCK;
        }
    size_t getall = new_offset + total;
    size_t new_end = offset + size;

    char *mem =  malloc(total);
    if (mem == NULL)
        {
        if(loglevel > 0)
            syslog(LOG_DEBUG,
                 "Cannot allocate memory %ld\n", total);
     	res = -ENOMEM; return res;
        }
    memset(mem, '\0', total);        // Zero it
    if (loglevel > 2)
        {
        syslog(LOG_DEBUG,
             "Reading: '%s' fsize=%ld\n", path, fsize);
        }
    if (loglevel > 3)
        {
        syslog(LOG_DEBUG,
            "Read par: new_offs=%ld new_end=%ld\n",
                                            new_offset, new_end);
        syslog(LOG_DEBUG,
            "Read par2: total=%ld skip=%ld\n",
                                            total, skip);
        }

    // Close to end of file
    if(getall > fsize)
        {
        if (loglevel > 3)
            {
            syslog(LOG_DEBUG, "getall=%ld fsize=%ld\n", getall,  fsize);
            }

        // Last block, load it
        // Always read full blocks from sideblock
        char *bbuff = NULL;
        int ret = read_sideblock(path, &bbuff, HS_BLOCK);
        if(!bbuff)
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Cannot alloc for sideblock.\n");
            errno = -ENOMEM;
            goto endd;
            }
        if(ret < 0)
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Cannot read sideblock data.\n");
            // Still could be good, an buffer is all zeros
            }
        else
            {
            //hs_decrypt(bbuff, HS_BLOCK, passx, plen);
            }

        if (loglevel > 2)
            syslog(LOG_DEBUG, "Got sideblock: '%s'\n",
                                    bluepoint2_dumphex(bbuff, 8));

        // Foundation is the sideblock data, copy it in
        size_t last = ((total / HS_BLOCK) - 1) * HS_BLOCK;

        if (loglevel > 2)
            syslog(LOG_DEBUG, "Patching in last block last=%ld\n", last);

        memcpy(mem + last, bbuff, HS_BLOCK);
        kill_buff(bbuff, HS_BLOCK);

        // Add in data from file
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Read blocks from file len=%ld\n", size);

        size_t res2 = pread(fi->fh, mem + skip, size, offset);
        if (res2 < 0 )
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Cannot read enc data size=%ld offs=%ld\n",
                        size, new_offset);

            res = res2;
            goto endd;
            }
        // Added data from file
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Read in from file res2=%ld\n", res2);

        hs_decrypt(mem, total, passx, plen);

        // Cheat ... we know we got that much
        res = res2;
        }
    else
        {
        res = pread(fi->fh, mem, total, new_offset);
        hs_decrypt(mem, total, passx, plen);
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Read full res=%d\n", res);
        }

    // Encryption / decryption by block size

    // Copy out newly decoded buffer
    memcpy(buf, mem + skip, size);

    // Set FP to old position + size
    lseek(fi->fh, oldoff + res, SEEK_SET);

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Read in data: '%s' size %d\n", path, res);

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




