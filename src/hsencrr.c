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

#include "hsencsb.h"
#include "hsencfs.h"

int     virt_read(const char *path, int fd, char *buf, uint wsize, uint offset)

{
    int ret = 0;
    uint new_offs = (offset / HS_BLOCK) * HS_BLOCK;
    uint endd = offset + wsize;
    uint new_end  = (endd / HS_BLOCK) * HS_BLOCK;
    if(endd % HS_BLOCK)
        new_end += HS_BLOCK;

    hslog(3, "virt_read(): new_offs=%ld new_end=%ld\n", new_offs, new_end);

    // Read in full blocks
    int xsize = new_end - new_offs;
    char *mem = malloc(xsize);
    if(!mem)
        {
        ret = -ENOMEM;
        goto end_func;
        }
    memset(mem, '\0', xsize);
    //hslog(3, "virt_read(): pread() new_offs=%ld new_end=%ld\n", new_offs, new_end);

    int res2a = pread(fd, mem, xsize, new_offs);
    if(res2a < 0)
        {
        ret =  -errno;
        goto end_func2;
        }
    // Read in last block from sideblock file
    sideblock_t *psb =  alloc_sideblock();
    if(psb == NULL)
        {
        hslog(1, "Cannot allocate memory for sideblock\n");
        ret = -errno;
        goto end_func2;
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
        //hslog(9, "Patching in side block last=%ld serial=%d\n", new_end / HS_BLOCK, psb->serial);
        // Foundation is the sideblock data, copy it in
        //if(psb->serial == new_end / HS_BLOCK)
        //     memcpy(mem + xsize - HS_BLOCK, psb->buff, HS_BLOCK);
        }
    kill_sideblock(psb);

    //hslog(3, "virt_read(): got=%ld xsize=%ld\n", res2a, xsize);

    hs_decrypt(mem, xsize, passx, plen);
    memcpy(buf, mem + (offset - new_offs), wsize);
    ret = wsize;     // Tell them we got it

    end_func2:
        free(mem);

   end_func:
    return ret;
}

//
// Read intercept
//

int xmp_read(const char *path, char *buf, size_t wsize, off_t offset, // )
                         struct fuse_file_info *fi)

{
	int res = 0;

    hslog(2, "@@ xmp_read(): fh=%ld '%s'\n", fi->fh, path);
    hslog(2, "xmp_read(): fh=%ld wsize=%ld offs=%ld\n", fi->fh, wsize, offset);

    #ifdef BYPASS
    int res2a = pread(fi->fh, buf, wsize, offset);
    if(res2a < 0) {
        return -errno;  }
    else  {
            //hs_decrypt(buf, wsize, passx, plen);
            return res2a;   }
    #endif

    #ifdef VIRTUAL
    res = virt_read(path, fi->fh, buf, wsize, offset);
    #endif

    return res;
}

// EOF