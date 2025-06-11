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
// Wed 07.Jul.2021      Virtual based remake started

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

#include "hsencsb.h"
#include "hsencfs.h"

#include "hs_crypt.h"
#include "bluepoint2.h"
#include "hsutils.h"

int     virt_write(const char *path, int fd, const char *buf, uint wsize, uint offset)

{
    int old_errno = errno, ret = 0;
    uint new_offs = (offset / HS_BLOCK) * HS_BLOCK;
    uint endd = offset + wsize;
    uint new_end  = (endd / HS_BLOCK) * HS_BLOCK;
    if(endd % HS_BLOCK)
        new_end += HS_BLOCK;

    old_errno = errno;
    lseek(fd, offset, SEEK_CUR);
    errno = old_errno;

    hslog(3, "virt_write(): '%s' wsize=%ld offset=%ld\n", path, wsize, offset);

    int xsize = new_end - new_offs;
    hslog(5, "virt_write(): new_offs=%ld new_end=%ld\n", new_offs, new_end);

    //off_t ofsize = get_fsize(fd);
    off_t ofsize =  get_sidelen(path);
    off_t oldoff = lseek(fd, 0, SEEK_CUR);

    hslog(5, "virt_write(): ofsize=%ld oldoff=%ld\n", ofsize, oldoff);

    // Read in ALL EXISING blocks to mem
    char *mem = malloc(xsize + 1);
    if(!mem)
        {
        //hslog(1, "virt_write(): cannot alloc memory xsize=%d\n", xsize);
        ret = -ENOMEM;
        goto end_func;
        }
    memset(mem, '\0', xsize);
    hs_encrypt(mem, xsize, defpassx, defplen);

    //   ofsize  |          |        wsize     |
    // ------------------------------------------------------
    //           ^ EOF      ^ offset           ^ new EOF

    // Read Original, as much as possible
    int res2a = pread(fd, mem, xsize, new_offs);
    if(res2a < 0)
        {
        hslog(3, "virt_write(): read error res2a=%lx, errno=%d\n",  res2a, errno);
        // Ignore pre read error
        //  ret =  -errno;  goto end_func2;
        }
    hslog(3, "virt_write(): read res2a=%lx bytes\n",  res2a);

    hs_decrypt(mem, xsize, defpassx, defplen);
    memcpy(mem + (offset - new_offs), buf, wsize);
    hs_encrypt(mem, xsize, defpassx, defplen);

    // Make sure our auxilliary ops did not create an error condition
    //errno = old_errno;

    // The actual write writes out all of it
    int res3a = pwrite(fd, mem, xsize, new_offs);
    //int res3a = pwrite(fd, mem + (offset - new_offs), wsize, offset);
    if(res3a < 0)
        {
        hslog(3, "virt_write(): error xsize=%ld errno=%d\n", errno, xsize);
        //ret = -errno;  goto end_func2;
        }

    hslog(5, "virt_write(): res3a=%ld xsize=%ld\n", res3a, xsize);
    ret = wsize;     // Tell them we got it

    // Write sideblock
    sideblock_t *psb = alloc_sideblock();
    if(psb == NULL) {
        hslog(1, "virt_write(): cannot alloc sideblock");
        ret = -ENOMEM;  goto end_func2;
        }
    int ret3 = read_sideblock(path, psb);
    size_t newsize =  MAX(offset + wsize, psb->flen);
    hslog(3, "virt_write(): newsize=%ld xsize=%ld\n", newsize, xsize);
    psb->flen = newsize;

    int ret2 = write_sideblock(path, psb);
    if(ret2 < 0)
        {
        hslog(1, "Error on sideblock write %d\n", errno);
	    //res = -errno;
        //goto endd;
        }
    kill_sideblock(psb);

  end_func2:
    free(mem);

    old_errno = errno;
    lseek(fd, offset + wsize, SEEK_CUR);
    errno = old_errno;

   end_func:
    return ret;
}

int xmp_write(const char *path, const char *buf, size_t wsize, // )
                        off_t offset, struct fuse_file_info *fi)
{
	int res = 0;

	if(fi == NULL)
        return -ENOSYS;

    if(wsize == 0)
        {
        hslog(1, "xmp_write(): zero write length on '%s'\n", path);
        return 0;
        }
    hslog(2, "xmp_write(): fh=%ld '%s' errno=%d\n",
                        fi->fh, path, errno);

    int old_errno = errno;
    off_t orgfsize = get_fsize(fi->fh);
    off_t oldoff = lseek(fi->fh, 0, SEEK_CUR);
    errno = old_errno;

    hslog(3, "xmp_write(): orgfsize=%lu oldoff=%lx errno=%d\n", orgfsize, oldoff, errno);
    hslog(3, "xmp_write(): fh=%ld wsize=%lu offs=%lu\n", fi->fh, wsize, offset);
    //errno = 0;

    // This is a test case for evaluating the FUSE side of
    // the system (it is OK)
    #ifdef BYPASS
        hslog(3, "xmp_write(): bypass fh=%ld wsize=%lu offs=%lu\n",
                        fi->fh, wsize, offset);
        int res2a = pwrite(fi->fh, buf, wsize, offset);
    	if (res2a < 0) {
            hslog(4, "xmp_write(): bypass error: %d %s",
                                        errno, strerror(errno));
            return -errno;
            }
        else
            {
            hslog(3, "xmp_write(): return ret=%d\n", res2a);
            return res2a;
            }
    #else
        // Simplified algorythm
        res = virt_write(path, fi->fh, buf, wsize, offset);
    #endif

    return res;
}

// EOF
