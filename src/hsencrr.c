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

#include "hsencdef.h"
//#include "hsencfs.h"
#include "hspass.h"
#include "hsencsb.h"
#include "hs_crypt.h"
#include "bluepoint2.h"
#include "hsutils.h"
#include "xmalloc.h"

int     virt_read(const char *path, int fd, char *buf, uint wsize, uint offset)

{
    int ret = 0;
    uint new_offs = (offset / HS_BLOCK) * HS_BLOCK;
    uint endd = offset + wsize;
    uint new_end  = (endd / HS_BLOCK) * HS_BLOCK;
    if(endd % HS_BLOCK)
        new_end += HS_BLOCK;

    int old_errno = errno;
    lseek(fd, offset, SEEK_CUR);
    errno = old_errno;

    hsprint(TO_EL, 6, "virt_read() new_offs=%ld new_end=%ld", new_offs, new_end);

    // Read in full blocks
    int xsize = new_end - new_offs;
    char *mem = xmalloc(xsize);
    if(!mem)
        {
        ret = -ENOMEM;
        goto end_func;
        }
    memset(mem, '\0', xsize);
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
        hsprint(TO_EL, 1, "Cannot allocate memory for sideblock");
        ret = -errno;
        //goto end_func2;
        }
    // Last block, load it
    int ret3 = read_sideblock(path, psb);
    if(ret3 < 0)
        {
        hsprint(TO_EL, 1, "Cannot read sideblock data.");
        // Ignore, still could be good
        }
    if(psb)
        xsfree(psb);

    hsprint(TO_EL, 7, "virt_read() res2a=%ld xsize=%ld", res2a, xsize);

    hs_decrypt(mem, xsize, defpassx,  sizeof(defpassx));
    memcpy(buf, mem + (offset - new_offs), wsize);
    ret = wsize;     // Tell them we got it

   end_func2:
    xsfree(mem);

    old_errno = errno;
    lseek(fd, offset + wsize, SEEK_CUR);
    errno = old_errno;

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

    hsprint(TO_EL, 3, "xmp_read() fh=%ld '%s'", fi->fh, path);
    hsprint(TO_EL, 4, "xmp_read() wsize=%ld offs=%ld", wsize, offset);

    #ifdef BYPASS
    int res2a = pread(fi->fh, buf, wsize, offset);
    if(res2a < 0) {
        hsprint(TO_EL, 2, "xmp_read() error errno=%d", errno);
        return -errno;
        }
    else
        {
        hsprint(TO_EL, 4, "xmp_read() fh=%ld wsize=%ld offs=%ld", fi->fh, wsize, offset);
        return res2a;
        }
    #else
        // Simplified algorythm
        res = virt_read(path, fi->fh, buf, wsize, offset);
    #endif

    return res;
}

// EOF