// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//
// Here is the task:
//
//      Intercept  write. Expand boundaries to match encryption
//      block boundaries.
//      If last block, gather data from sideblock, patch it in.
//      Decrypt / Encrypt.
//      Patch required data back.
//      Save new sideblock
//
// Tue 06.Jul.2021      sideblock system removed, fake encryption passes
// Wed 07.Jul.2021      sideblock system reworked
// Fri 16.Jul.2021      zigjump under scrutini
// Sun 08.Aug.2021      still fighting with it

//
// Read / Write the data coming from the user.
//      If last block, gather data from sideblock, patch it in.
//

// -----------------------------------------------------------------------
// Intercept write. Make it block size aligned, both beginning and end.
// This way encryption / decryption is symmetric.
//

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <fuse.h>
#include <ulockmgr.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <sys/time.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <signal.h>
#include <getopt.h>

#include "base64.h"

#include "../bluepoint/hs_crypt.h"
#include "../bluepoint/bluepoint2.h"
#include "../common/hsutils.h"

#include "hsencfs.h"

int xmp_write(const char *path, const char *buf, size_t wsize, // )
                        off_t offset, struct fuse_file_info *fi)
{
	int res = 0, loop = 0, fd = -1;

    //(void) fi;
	if(fi == NULL)
		fd = open(path, O_RDWR);
	else
		fd = fi->fh;

    if(wsize == 0)
        {
        hslog(1, "zero write on '%s'\n", path);
        return 0;
        }

    hslog(LOG_DEBUG, "xmp_write(): fh=%ld wsize=%lu offs=%lu\n",
                                fd, wsize, offset);

    // This is a test case for evaluating the FUSE side of the system (it is OK)
    #ifdef BYPASS
        // Only enable position independent algorithm (aka FAKE)
        //hs_encrypt(buf, wsize, passx, plen);
        int res2a = pwrite(fd, buf, wsize, offset);
    	if (res2a < 0) {
            return -errno; }
        else {
            return res2a;  }
    #endif

    // Change file handle to reflect read / write
    //int ret3 = fchmod(fd, S_IRUSR | S_IWUSR |  S_IRGRP);
    //if (retls3 < 0)
    //    if (loglevel > 0)
    //    syslog(LOG_DEBUG,
    //            " Cannot change mode on write '%s'\n", path);

    // Save current file parameters, as the FS sees it
    //off_t oldoff = lseek(fd, 0, SEEK_CUR);

    off_t fsize = get_fsize(fd);
    hslog(4, "File %s fh=%d fsize=%ld\n", path, fd, fsize);

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

    //hslog(3, "Write: offs=%ld wsize=%ld fsize=%ld\n", offset, wsize, fsize);

    sideblock *psb = alloc_sideblock();
    if(psb == NULL) {
        res = -ENOMEM;  goto endd;
        }

    // Here we prepare the sideblock for partial read
    //hs_encrypt(psb->buff, HS_BLOCK, passx, plen);

    // Writing past end of file, padd it
    // ==---------|======================================
    //    | skip  |fsize   |offset         |op_end    |new_end
    //    |fsize2 |        |    wsize      |          |
    //    |       mlen3                    |          |
    //    |     skip2      |   --> updated            |
    //    |new_beg                                    |
    //    | skip  |                                   |
    //    |              total                        |

    int fsize2 = fsize, skip2 = skip, mlen4 = 0;

    void *mem =  NULL;
    // Was an op past EOF? -
    if(new_end > fsize)
        {
        mem =  hsalloc(total);
        }
    else if(op_end > fsize)
        {
        mem =  hsalloc(total);
        }
    else if(offset > fsize)
        {
        fsize2 = (fsize / HS_BLOCK) * HS_BLOCK;
        new_beg = fsize2;
        total  = new_end - fsize2;     predat = total - HS_BLOCK;
        skip2  = offset  - fsize2;     mlen4  = fsize   - fsize2;
        predat = total - HS_BLOCK;

        mem =  hsalloc(total);
        }
    else if(new_beg > fsize)
        {
        }
    else
        {
        mem =  hsalloc(total);
        }
    if(!mem)
        {
        goto endd;
        }

    //hslog(3, "Malloc hsalloc: %d\n", total);
    hs_encrypt(mem, total, passx, plen);

    //if(offset > fsize2)  // Was seek past EOF? -- process
    //    {   // Get original
    //    //hslog(3, "Pad EOF fsize2=%ld mlen4=%lld\n", fsize2, mlen4);
    //    int ret3 = pread(fd, mem, mlen4, fsize2);
    //    }
    //else
        {   // Get original content, as much as available
        //int ret4 = pread(fd, mem, total, fsize2);
        //int ret4 = pread(fd, mem, total, new_beg);
        //hslog(2, "Got org content %d bytes.\n", ret4);
        }

    // Past file end?
    if(new_end >= fsize2)
        {
        size_t padd = new_end - fsize;
        hslog(3, "=== Past EOF: fd=%d fsize=%lld padd=%ld\n", fd, fsize2, padd);

        // Close to end: Sideblock is needed
        int ret = read_sideblock(path, psb);
        if(ret < 0)   // Still could be good, buffer is all zeros (or known)
            hslog(2, "Cannot read sideblock data.\n");

        //hslog(2, "Sideblock ret=%d serial=%d current=%d\n", ret, psb->serial, op_end / HS_BLOCK);

        // Patch sideblock back in:
        //if(psb->serial ==  new_end / HS_BLOCK)
        if(psb->serial ==  op_end / HS_BLOCK)
            {
            //int ret4 = pread(fd, mem, predat, new_beg);
            //hslog(2, "Readp: sb=%d predat=%lld fsize2=%lld ret4=%d\n", psb->serial, predat, fsize2, ret4);
            memcpy(mem + predat, psb->buff, HS_BLOCK);
            }
        else
            {
            //hslog(2, "Mismatch: Sideblock serial=%d current=%d\n", psb->serial, new_end / HS_BLOCK);
            //int ret5 = pread(fd, mem, total, new_beg);
            //hslog(2, "Readf: total=%lld fsize2=%lld ret4=%d\n", total, new_beg, ret5);
            }
        }
    else
        {
        int ret6 = pread(fd, mem, total, new_beg);
        hslog(2, "Full Read: total=%lld fsize2=%lld ret4=%d\n", total, fsize2, ret6);
        }

    // Buffer now in, complete; decrypt it
    hs_decrypt(mem, total, passx, plen);

    hslog(2, "WR out: wsize=%ld offs=%ld skip2=%ld\n",  wsize, offset, skip2);

    // Grab the new data
    memcpy(mem + skip2, buf, wsize);

    // Encryption / decryption by block size
    hs_encrypt(mem, total, passx, plen);

    // Write it back out, all that changed

    if(offset > fsize)
        {
        int res3 = pwrite(fd, mem + mlen4, op_end - fsize, fsize);
    	if (res3 < 0)
            {
            hslog(1, "Err writing file: %s res %d errno %d\n", path, res, errno);
    		res = -errno;
            goto endd;
            }
        res = MIN(wsize, res3);
        }
    else
        {
        //hslog(1, "Att wr:total=%lld, offs=%lld", total, fsize2);
        //int res4 = pwrite(fd, mem + skip, wsize, new_beg);
        int res4 = pwrite(fd, mem, wsize + skip, new_beg);
    	if(res4 < 0)
            {
            hslog(1, "Err writing file: %s res %d errno %d\n", path, res, errno);
            res = -errno;
            goto endd;
            }
        res = wsize;
        }
    //hslog(9, "Written: res %d bytes\n", res);

    //if(new_end >= fsize)
        {
        size_t padd = new_end - fsize;
        // Write sideblock back out

        psb->serial = new_end / HS_BLOCK;
        //psb->serial = op_end / HS_BLOCK;
        hslog(7, "Wr SB: ser=%d new_b=%ld pdat=%ld tot=%ld\n",
                                                psb->serial, new_beg, predat, total);
        //if(predat > 4096)
        //    memcpy(psb->buff, (mem + total) -  2 * HS_BLOCK, 2 * HS_BLOCK);
        //else

        memcpy(psb->buff, (mem + total) - HS_BLOCK, HS_BLOCK);

        int ret2 = write_sideblock(path, psb);
        if(ret2 < 0)
            {
            hslog(1, "Error on sideblock write %d\n", errno);
    	    //res = -errno;
            //goto endd;
            }
        }

    // Reflect new file position  (not needed)
    //lseek(fd, offset + res, SEEK_SET);

   endd:
    // Do not leave dangling data behind
    kill_buff(mem, total);
    kill_sideblock(psb);
	return res;
}

// EOF
