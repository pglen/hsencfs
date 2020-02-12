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

static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)

{
	int res = 0;

    if (loglevel > 3)
        {
        syslog(LOG_DEBUG,
            "xmp_read(): '%s' size=%ld offs=%ld\n", path, size, offset);
        }

    // Remember old place, get size
    off_t fsize = get_fsize(fi->fh);  off_t oldoff = lseek(fi->fh, 0, SEEK_SET);

    // This is done to complete the buffers for encryption. Special for last.
    // Vars with underscore are points, others are intervals
    //               |         size        |                    | end_offset
    // ===-----------|---------------------|--------------==============
    //     |  skip   ^ offset              ^getting       ^ fsize
    //     ^ beg_offset (buf % n)                               | total
    //                                         |  - sideblock - |
    //     |              last                 |

    // Pre-calc all parameters
    size_t beg_offset = (offset / HS_BLOCK) * HS_BLOCK;
    size_t skip = offset - beg_offset;
    size_t getting = offset + size;
    size_t end_offset = (getting / HS_BLOCK) * HS_BLOCK;
    if((getting % HS_BLOCK) > 0)     // Expand with one full block
        {
        end_offset += HS_BLOCK;
        }
    size_t total = end_offset - beg_offset;
    size_t last = (end_offset - HS_BLOCK) - beg_offset;

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
            "Read par: new_offs=%ld end_offset=%ld\n",
                                            beg_offset, end_offset);
        syslog(LOG_DEBUG,
            "Read par2: total=%ld skip=%ld\n",
                                            total, skip);
        }

    // Close to end of file
    if(end_offset >= fsize)
        {
        if (loglevel > 3)
            {
            syslog(LOG_DEBUG, "fsize=%ld\n", fsize);
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

        if (loglevel > 2)
            syslog(LOG_DEBUG, "Got sideblock: '%s'\n",
                                    bluepoint2_dumphex(bbuff, 8));

        // Foundation is the sideblock data, copy it in

        if (loglevel > 2)
            syslog(LOG_DEBUG, "Patching in last block last=%ld\n", last);

        memcpy(mem + last, bbuff, HS_BLOCK);
        kill_buff(bbuff, HS_BLOCK);

        // Add in data from file
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Read blocks from file len=%ld\n", size);

        size_t res2 = pread(fi->fh, mem, fsize - beg_offset, beg_offset);
        if (res2 < 0 )
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Cannot read enc data size=%ld offs=%ld\n",
                        size, beg_offset);

            res = res2;
            goto endd;
            }
        // Added data from file
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Read in from file res2=%ld\n", res2);

        // Cheat ... we know we got that much
        res = res2;
        }
    else
        {
        res = pread(fi->fh, mem, total, beg_offset);
        if (loglevel > 2)
            syslog(LOG_DEBUG, "Read full res=%d\n", res);
        }

    // Encryption / decryption by block size
    //char *cmem = (char*)mem;
    //for (int aa = 0; aa < total; aa += HS_BLOCK)
    //    {
    //    hs_decrypt(cmem + aa, HS_BLOCK, passx, plen);
    //    }

    hs_decrypt(mem, total, passx, plen);

    // Copy out newly decoded buffer
    memcpy(buf, mem + skip, size);

    // Set FP to old position + size
    //lseek(fi->fh, oldoff + res, SEEK_SET);

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Read in data: '%s' size %d\n", path, res);

  endd:

    // Do not leave data behind
    if (mem)
        {
        kill_buff(mem, total);
        }
	return res;
}

// EOF





