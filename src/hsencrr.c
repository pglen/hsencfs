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
// Intercept read. Make it block size even, so encryption / decryption
// is symmetric.
//
// Exception is taken when dealing with the last block. The sideblock Inode file contains a copy
// of the last block, one that overflows the real file length.
// This is to complete the last buffer.
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
    // Remember old place, get size
    off_t fsize = get_fsize(fi->fh); off_t oldoff = lseek(fi->fh, 0, SEEK_SET);

    // Pre-calc all parameters
    size_t new_offset = (offset / HS_BLOCK) * HS_BLOCK;
    size_t skip = offset - new_offset;
    size_t total = ((size + skip) / HS_BLOCK) * HS_BLOCK;
    if((size % HS_BLOCK) != 0) {
        // Expand with one full block
        total += HS_BLOCK;
        }
    size_t getall = new_offset + total;
    size_t infile = fsize - new_offset;
    size_t get_end = offset + size;
    size_t new_end = (get_end / HS_BLOCK) * HS_BLOCK;
    if(new_end > fsize)
        {
        new_end = (fsize / HS_BLOCK) * HS_BLOCK;
        }

    char *mem =  malloc(total);
    if (mem == NULL)
        {
     	res = -ENOMEM;
        return res;
        }
    memset(mem, '\0', total);        // Zero it
    if (loglevel > 2)
        {
        syslog(LOG_DEBUG, "Reading file: '%s' fsize=%ld size=%ld offs=%ld\n",
                                                           path, fsize, size, offset);
        }
    if (loglevel > 3)
        {
        syslog(LOG_DEBUG, "Size expanded: new_offs=%ld new_end=%ld total=%ld skip=%ld\n",
                                            new_offset, new_end, total, skip);
        }

    // Always read  full blocks
    char *bbuff = NULL;

    if(getall > fsize)
        {
        if (loglevel > 3)
            {
            syslog(LOG_DEBUG, "getall=%ld infile=%ld fsize=%ld\n",
                                                                   getall, infile, fsize);
            }

        // Last block, load it
        int ret = read_sideblock(path, &bbuff, HS_BLOCK);
        if(!bbuff)
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Cannot alloc for sideblock\n");
            goto endd;
            }

        //
        if(ret < 0)
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Cannot read sideblock data\n");
            }
        else
            {
            hs_decrypt(bbuff, HS_BLOCK, passx, plen);
            }

        if (loglevel > 2)
            syslog(LOG_DEBUG, "Got sideblock file: '%s'\n",
                                    bluepoint2_dumphex(bbuff, 16));

        // Read in last sideblock data
        size_t dlen = new_end - new_offset;
        if(dlen == 0)
            {
            // No sideblock needed
            goto endd;
            }
        int res2 = pread(fi->fh, mem, dlen, new_offset);
        if (res2 <= 0 )
            {
            if (loglevel > 2)
                syslog(LOG_DEBUG, "Cannot read enc data len=%ld offs=%ld\n",
                dlen, new_offset);
            goto endd;
            }
        hs_decrypt(mem, dlen, passx, plen);

        // Add sideblock data to the end
        memcpy(mem + dlen, bbuff, total - dlen);
        // Do not leave data behind
        if (bbuff)
            {
            // Just to confuse the would be decoder
            hs_decrypt(bbuff, HS_BLOCK, "pass", 4);
            memset(bbuff, 0, HS_BLOCK);        // Zero it
            free(bbuff);
            }

        // Cheat ... we got it all
        res = size;
        }
    else
        {
        res = pread(fi->fh, mem, total, new_offset);
        // Encryption / decryption by block size
        hs_decrypt(mem, total, passx, plen);
        }

    // Copy out newly decoded buffer
    memcpy(buf, mem + skip, size);

    // Restore old position + size, increment
    lseek(fi->fh, oldoff + res, SEEK_SET);

    if (loglevel > 2)
        syslog(LOG_DEBUG, "Read in data: '%s' size %d\n", path, res);

  endd:

    // Do not leave data behind
    if (mem)
        {
        // Encrypt (double decrypt) it: This is a fake encryption of the dangling memory.
        // Just to confuse the would be decoder
        hs_decrypt(mem, total, "pass", 4);
        memset(mem, 0, total);        // Zero it
        free(mem);
        }
	return res;
}


// EOF




