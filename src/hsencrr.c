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
// Wed 07.Jul.2021      Virtual based remake started

// -----------------------------------------------------------------------
// Intercept read. Make it block size, (HS_BLOCK) so encryption / decryption
// is symmetric.
//
// Exception is taken when dealing with the last block. The sideblock file
// contains a copy of the last block, one that overflows the real file length.
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

#include "../bluepoint/hs_crypt.h"
#include "../bluepoint/bluepoint2.h"
#include "../common/hsutils.h"

#include "hsencfs.h"

//
// Read intercept
//

int xmp_read(const char *path, char *buf, size_t wsize, off_t offset, // )
                         struct fuse_file_info *fi)

{
	int res = 0;

    //hslog(2, "@@ xmp_read(): fh=%ld '%s'\n", fi->fh, path);
    hslog(3, "xmp_read(): fh=%ld wsize=%ld offs=%ld\n", fi->fh, wsize, offset);

    #ifdef BYPASS
    int res2a = pread(fi->fh, buf, wsize, offset);
    if(res2a < 0) {
        return -errno;  }
    else  {
            //hs_decrypt(buf, wsize, passx, plen);
            return res2a;   }
    #endif

    #ifdef VIRTUAL
    int res2a = pread(fi->fh, buf, wsize, offset);
    if(res2a < 0) {
        return -errno;  }
    else  {
            return res2a;   }
    #endif

    // Remember old place, get wsize
    off_t fsize = get_fsize(fi->fh);
    //off_t oldoff = lseek(fi->fh, 0, SEEK_CUR);

    // This is done to complete the buffers for encryption. Special for last.
    // Vars with underscore are points, others / circumflex marks (^) are intervals
    //               |^ buf                |
    //               |        size         |                    | end_offset
    // ====----------|---------------------|--------------==============
    //     |  skip   ^ offset              ^ getting     ^ fsize
    //     ^ beg_offset (buf % HS)       total           | EOF
    //     |                                   |  - sideblock - |
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
        hslog(0, "Cannot allocate memory for hsread %ld\n", total);
     	res = -ENOMEM; return res;
        }
    memset(mem, '\0', total);                   // Zero it
    hslog(9,  "Reading: '%s' fsize=%ld\n", path, fsize);

    //hslog(9, "Read par: new_offs=%ld end_offset=%ld\n", beg_offset, end_offset);

    // Close to end of file
    if(end_offset >= fsize)
        {
        hslog(3, "Past EOF offs=%ld size=%ld fsize=%ld\n", offset, wsize, fsize);

        size_t res2 = pread(fi->fh, mem, fsize - beg_offset, beg_offset);
        if (res2 < 0)
            {
            hslog(0, "Cannot read size=%ld offs=%ld\n", wsize, beg_offset);
            res = res2;
            goto endd;
            }
        // Add in data from file
        hslog(2, "Read blocks from file res2=%ld\n", res2);

        // Added data from file
        //hslog(9, "Read in from file res2=%ld\n", res2);
        res = res2;

        // Read in last block from sideblock file
        sideblock *psb =  alloc_sideblock();
        if(psb == NULL)
            {
            hslog(1, "Cannot allocate memory for sideblock '%s'\n", path);
            res = -errno;
            goto endd;
            }
        // Last block, load it
        int ret3 = read_sideblock(path, psb);
        if(ret3 < 0)
            {
            hslog(1, "Cannot read sideblock data.\n");
            // Ignore, still could be good
            }
        else
            {
            hslog(9, "Patching in side block last=%ld serial=%d\n", last, psb->serial);
            // Foundation is the sideblock data, copy it in
            if(psb->serial == end_offset / HS_BLOCK)
                 memcpy(mem + last, psb->buff, HS_BLOCK);
            }
        kill_sideblock(psb);
        }
    else
        {
        int ret5 = pread(fi->fh, mem, total, beg_offset);
        if(ret5 < 0)
            {
            res = -errno;
            goto endd;
            }
        hslog(9, "Read full res=%d\n", res);
        res = wsize;
        }
    hs_decrypt(mem, total, passx, plen);

    // Copy out newly decoded buffer
    memcpy(buf, mem + skip, wsize);

    hslog(1, "Read in data: '%s' size %d\n", path, res);

  endd:
    // Do not leave data behind
    kill_buff(mem, total);
	return res;
}

// EOF