// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//
// Extracted for eazy editing. This code took forever.
//
// Side block handling
//
// -----------------------------------------------------------------------

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
#include <sys/time.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <signal.h>
#include <getopt.h>

#include "hsencdef.h"
#include "hsencfs.h"
#include "hspass.h"
#include "base64.h"
#include "hsencsb.h"
#include "xmalloc.h"
#include "hs_crypt.h"
#include "bluepoint2.h"
#include "hsutils.h"

sideblock_t *alloc_sideblock()

{
    sideblock_t *psb = xmalloc(sizeof(sideblock_t));
    if(psb == NULL)
        {
        hslog(1, "Cannot allocate memory for sideblock\n");
        goto endd;
        }
    INIT_SIDEBLOCK(*psb);
    //memset(psb->buff, '\0', sizeof(psb->buff));

   endd:

    return psb;
}

// -----------------------------------------------------------------------

char    *get_sidename(const char *path)

{
    char *ptmp2 = xmalloc(PATH_MAX);
    if(!ptmp2)
        {
        hslog(1,
            "Cannot allocate memory for sideblock filename '%s'\n", path);
        goto endd;
        }
    memset(ptmp2, '\0',  PATH_MAX);
    // hslog(9, "Generate sidename '%s'\n", path);
    int cnt = 0, cnt2 = 0; char *pch, *temp;
    char *ddd = xstrdup(path);
    pch = strtok(ddd, "/");
    while ( (temp = strtok (NULL, "/") ) != NULL)
        cnt++;
    xsfree(ddd);

    char *eee = xstrdup(path);
    strcpy(ptmp2, mountsecret);
    pch = strtok(eee, "/");
    if(cnt2 == cnt)
        strcat(ptmp2, "._");
    strcat(ptmp2, pch);

    //hslog(9, "sb tokenx '%s'\n", pch);

    while ( (temp = strtok(NULL, "/") ) != NULL)
        {
        cnt2++;
        //hslog(9, "sb token %d  '%s'\n", cnt2, temp);
        if(strcmp(temp, "."))
            {
            strcat(ptmp2, "/");
            if(cnt2 == cnt)
                strcat(ptmp2, "._");
            strcat(ptmp2, temp);
            }
        }
    xsfree(eee);
    strcat(ptmp2, myext);

    hslog(9, "Sidename: '%s'\n", ptmp2);
    //sizeof(sideblock_t));

   endd:
    return ptmp2;
}

// ----------------------------------------------------------------------
// Get (real) file size form sideblock

size_t get_sidelen(const char *path)

{
    size_t ret = 0;  int old_errno = errno;

    //if(strlen(path) == 1)
    //    return 0;

    hslog(9, "Get sideblock len from: '%s'\n", path);

    sideblock_t *psb = alloc_sideblock();
    if(psb == NULL) {
        hslog(1, "Error on sideblock malloc %d\n", errno);
	    //rret = -ENOMEM;
        goto end_func2;
        }
    int ret2 = read_sideblock(path, psb);
    if(ret2 < 0)
        {
        hslog(1, "Error on sideblock read %d\n", errno);
        goto end_func3;
        }
    ret = psb->flen;

  end_func3:
    xsfree(psb);
    //errno = old_errno;

   end_func2:
    //hslog(9, "sidelen: xmalloc_bytes %d", xmalloc_bytes);

    return ret;
}

// ----------------------------------------------------------------------
// Always read full blocks from sideblock

int    read_sideblock(const char *path, sideblock_t *psb)

{
    int ret = 0, old_errno = 0;

    hslog(9, "Read sideblock: '%s'\n", path);

    if(psb->magic !=  HSENCFS_MAGIC)
        {
        hslog(1, "Bad magic on sizeblock read '%s'\n", path);
        ret = -1;
        goto endd;
        }
    char *ptmpr =  get_sidename(path);
    if(!ptmpr)
        {
        hslog(1, "Cannot allocate sideblock filename '%s'\n", path);
        ret = -ENOMEM;
        goto endd;
        }
    //hslog(9, "Opening sideblock file '%s'\n", ptmpr);
    int fdi = open(ptmpr, O_RDWR);
    if(fdi < 0)
        {
        hslog(1, "Error on opening sideblock '%s', errno: %d\n",
                             ptmpr, errno);
        goto endd2;
        }
    int ret2 = read(fdi, psb, sizeof(sideblock_t));
    if(ret2 && ret2 < sizeof(sideblock_t))        // We ignore empty file
        {
        hslog(1, "Error on reading sideblock file, errno: %d\n", errno);
        }
    close(fdi);
    //errno = old_errno;
    if(psb->magic !=  HSENCFS_MAGIC)
        {
        hslog(1, "Error on sideblock MAGIC\n");
        }
    //hslog(9, "Got sideblock:, '%s'\n", bluepoint2_dumphex(*pbuff, 8));

  endd2:
    if (ptmpr) xsfree(ptmpr);
  endd:
    //hslog(9, "read sb xmalloc_bytes %d", xmalloc_bytes);

    return ret;
}

//////////////////////////////////////////////////////////////////////////
//
// Read / Write the
//      If last block, gather data from sideblock, patch it in.
//

int     write_sideblock(const char *path, sideblock_t *psb)

{
    int ret = 0;

    if(psb->magic !=  HSENCFS_MAGIC)
        {
        hslog(1, "Bad magic on sizeblock write '%s'\n", path);
        ret = -1;
        goto endd;
        }

    hslog(9, "Write sideblock: '%s'\n", path);

    char *ptmp2 =  get_sidename(path);
    if(!ptmp2)
        {
        hslog(1,
                "Cannot allocate memory for file name '%s'\n", path);
        goto endd;
        }

    //hslog(2, "Sidename '%s'\n", ptmp2 + 15);

    hslog(9, "Writing sideblock file '%s'\n", ptmp2);

    int rrr = 0, old_errno = errno;
    int fdi = open(ptmp2, O_RDWR);
    if(fdi < 0)
        {
        hslog(1, "Error on creating sideblock file '%s', errno: %d\n",
                        ptmp2, errno);

        ret = -errno;
        errno = old_errno;
        goto endd2;
        }
    rrr = write(fdi, psb, sizeof(sideblock_t));
    if(rrr < sizeof(sideblock_t))
        {
        hslog(1, "Error on writing sideblock file, errno: %d\n", errno);
        ret = -errno;
        }
    close(fdi);

    //hslog(1, "Writing sideblock file2 '%s'\n", ptmp2);

    errno = old_errno;

    // hslog(4, "Written sideblock file, '%s'\n",
    //            bluepoint2_dumphex(bbuff, 16));

   endd2:
        hslog(9, "Writing sideblock file3 '%s'\n", ptmp2);

    xsfree(ptmp2);

  endd:
    return ret;
}

int    create_sideblock(const char *path)

{
    int ret = 0, old_errno = errno;

    char *ptmpc = get_sidename(path);
    if(!ptmpc)
        {
        hslog(1, "Canot allocate sideblock memory on '%s'", path);
        ret = -ENOMEM;
        goto endd;
        }
    //hslog(3, "Sideblock created '%s'\n", ptmp2 + 15);
    sideblock_t *psb = alloc_sideblock();
    if(!psb)
        {
        ret = -ENOMEM;
        goto endd2;
        }
    int fdi = open(ptmpc, O_RDWR | O_CREAT | O_TRUNC , S_IRUSR | S_IWUSR);
    if(fdi < 0)
        {
        hslog(1, "Error on creating sideblock '%s' errno: %d\n",
                    ptmpc, errno);

        // Not sure what to do ... error?
        ret = -errno;
        goto endd3;
        }
    int ww = write(fdi, psb, sizeof(sideblock_t));
    if(ww < sizeof(sideblock_t))
        {
        ret = -ENOMEM;
        hslog(1, "Error on writing to sideblock errno: %d\n", errno);
        }

  endd4:
    close(fdi);
    errno = old_errno;

  endd3:
    xsfree(psb);

  endd2:
    xsfree(ptmpc);

   endd:
    return ret;
}

// EOF