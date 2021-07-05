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

static int xmp_read(const char *path, char *buf, size_t wsize, off_t offset, // )
                         struct fuse_file_info *fi)

{
	int res = 0;

    hslog(2, "@@ xmp_read(): fh=%ld '%s'\n", fi->fh, path);
    hslog(3, "xmp_read(): wsize=%ld offs=%ld\n", wsize, offset);

    #ifdef BYPASS
    int res2a = pread(fi->fh, buf, wsize, offset);
    if(res2a < 0) {
        return -errno;  }
    else  {
            //hs_decrypt(buf, wsize, passx, plen);
            return res2a;   }
    #endif

    // Remember old place, get wsize
    off_t fsize = get_fsize(fi->fh);
    off_t oldoff = lseek(fi->fh, 0, SEEK_CUR);

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
    size_t getting = offset + wsize;
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
    memset(mem, '\0', total);                   // Zero it
    if (loglevel > 2)
        {
        syslog(LOG_DEBUG,
             "Reading: '%s' fsize=%ld\n", path, fsize);
        }
    hslog(9, "Read par: new_offs=%ld end_offset=%ld\n", beg_offset, end_offset);

    // Close to end of file
    if(end_offset >= fsize)
        {
        hslog(3, "Past EOF offs=%ld size=%ld fsize=%ld\n", offset, wsize, fsize);
        // Read in last block from lastblock file
        sideblock *psb =  alloc_sideblock();
        if(psb == NULL)
            {
            hslog(0, "Cannot allocate memory for sideblock '%s'\n", path);
            res = -errno;
            goto endd;
            }
        // Last block, load it
        int ret = read_sideblock(path, psb);
        if(ret < 0)
            {
            hslog(2, "Cannot read sideblock data.\n");
            }
        else
            {
            hslog(9, "Patching in last block last=%ld\n", last);
            // Foundation is the sideblock data, copy it in
            memcpy(mem + last, psb->buff, HS_BLOCK);
            }
        kill_sideblock(psb);

        // Add in data from file
        hslog(2, "Read blocks from file len=%ld\n", wsize);

        size_t res2 = pread(fi->fh, mem, fsize - beg_offset, beg_offset);
        if (res2 < 0)
            {
            hslog(0, "Cannot read size=%ld offs=%ld\n", wsize, beg_offset);
            res = res2;
            goto endd;
            }
        // Added data from file
        hslog(9, "Read in from file res2=%ld\n", res2);
        // Cheat ... we know we got that much
        res = res2;
        }
    else
        {
        res = pread(fi->fh, mem, total, beg_offset);
        hslog(9, "Read full res=%d\n", res);
        }
    hs_decrypt(mem, total, passx, plen);
    // Copy out newly decoded buffer
    memcpy(buf, mem + skip, wsize);
    hslog(9, "Read in data: '%s' size %d\n", path, res);

  endd:
    // Do not leave data behind
    kill_buff(mem, total);
	return res;
}

// EOF