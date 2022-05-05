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

#include "hsencsb.h"
#include "hsencfs.h"

sideblock_t *alloc_sideblock()

{
    sideblock_t *psb = malloc(sizeof(sideblock_t));
    if(psb == NULL)
        {
        if (loglevel > 0)
           syslog(LOG_DEBUG, "Cannot allocate memory for sideblock\n");
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
    char *ptmp2 = malloc(PATH_MAX);
    if(!ptmp2)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Cannot allocate memory for sideblock filename '%s'\n", path);
        goto endd;
        }

     if (loglevel > 9)
        syslog(LOG_DEBUG, "Generate sidename '%s'\n", path);

    int cnt = 0, cnt2 = 0; char *pch, *temp;
    char *ddd = strdup(path);
    pch = strtok(ddd, "/");
    while ( (temp = strtok (NULL, "/") ) != NULL)
        cnt++;
    free(ddd);

    char *eee = strdup(path);
    strcpy(ptmp2, mountsecret);
    pch = strtok(eee, "/");
    if(cnt2 == cnt)
        strcat(ptmp2, ".");
    strcat(ptmp2, pch);
    //syslog(LOG_DEBUG, "sb tokenx '%s'\n", pch);

    while ( (temp = strtok(NULL, "/") ) != NULL)
        {
        cnt2++;
        //syslog(LOG_DEBUG, "sb token %d  '%s'\n", cnt2, temp);
        if(strcmp(temp, "."))
            {
            strcat(ptmp2, "/");
            if(cnt2 == cnt)
                strcat(ptmp2, ".");
            strcat(ptmp2, temp);
            }
        }
    free(eee);
    strcat(ptmp2, myext);

    if (loglevel > 9)
         syslog(LOG_DEBUG, "Got sidename '%s'\n", ptmp2);

   endd:
    return ptmp2;
}

// ----------------------------------------------------------------------
// Always read full blocks from sideblock

int    read_sideblock(const char *path, sideblock_t *psb)

{
    int ret = 0;

    if(psb->magic !=  HSENCFS_MAGIC)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Bad magic on sizeblock read '%s'\n", path);
        ret = -1;
        goto endd;
        }
    char *ptmp2 =  get_sidename(path);
    if(!ptmp2)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Cannot allocate memory for sideblock file name '%s'\n", path);

        ret = -ENOMEM;
        goto endd;
        }

    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "Opening sideblock file '%s'\n", ptmp2);

    int old_errno = errno;

    //int fdi = open(ptmp2, O_RDWR);
    //if(fdi < 0)
    //    {
    //    if (loglevel > 0)
    //        syslog(LOG_DEBUG, "Error on opening sideblock file '%s', errno: %d\n", ptmp2, errno);
    //
    //    ret = -ENOENT;
    //    //errno = old_errno;
    //    goto endd2;
    //    }
    //else
    //    {
    //    //ret = read(fdi, psb, sizeof(sideblock_t));
    //    //if(ret && ret < sizeof(sideblock_t))        // We ignore empty file
    //    //    {
    //    //    if (loglevel > 0)
    //    //        syslog(LOG_DEBUG, "Error on reading sideblock file, errno: %d\n", errno);
    //    //    //ret = -EFAULT;
    //    //    }
    //    //close(fdi);
    //    }

    errno = old_errno;
    if(psb->magic !=  HSENCFS_MAGIC)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on sideblock MAGIC\n");
        }

    //if (loglevel > 3)
    //    syslog(LOG_DEBUG, "Got sideblock:, '%s'\n", bluepoint2_dumphex(*pbuff, 8));

  endd2:
    free(ptmp2);

  endd:
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
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Bad magic on sizeblock write '%s'\n", path);
        ret = -1;
        goto endd;
        }

    char *ptmp2 =  get_sidename(path);
    if(!ptmp2)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Cannot allocate memory for file name '%s'\n", path);
        goto endd;
        }

    if (loglevel > 9)
        syslog(LOG_DEBUG, "Writing sideblock file '%s'\n", ptmp2);

    int rrr = 0, old_errno = errno;
    //int fdi = open(ptmp2, O_RDWR);
    //if(fdi < 0)
    //    {
    //    if (loglevel > 0)
    //        syslog(LOG_DEBUG, "Error on creating sideblock file '%s', errno: %d\n", ptmp2, errno);
    //
    //    ret = -errno;
    //    errno = old_errno;
    //    goto endd2;
    //    }
    //rrr = write(fdi, psb, sizeof(sideblock_t));
    //if(rrr < sizeof(sideblock_t))
    //    {
    //    if (loglevel > 0)
    //        syslog(LOG_DEBUG, "Error on writing sideblock file, errno: %d\n", errno);
    //
    //    //ret = -errno;
    //    }
    //close(fdi);

    //if (loglevel > 2)
    //    syslog(LOG_DEBUG, "Writing sideblock file2 '%s'\n", ptmp2);

    errno = old_errno;

    //if (loglevel > 4)
    //    syslog(LOG_DEBUG, "Written sideblock file, '%s'\n", bluepoint2_dumphex(bbuff, 16));

   endd2:
    if (loglevel > 9)
        syslog(LOG_DEBUG, "Writing sideblock file3 '%s'\n", ptmp2);

    free(ptmp2);

  endd:
    return ret;
}

int    create_sideblock(const char *path)

{
    int ret = 0;

    char *ptmp2 = get_sidename(path);
    if(!ptmp2)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Canot allocate sideblock memory.");
        ret = -ENOMEM;
        goto endd;
        }

    sideblock_t *psb = alloc_sideblock();
    if(!psb)
        goto endd2;

    int old_errno = errno;
    int fdi = open(ptmp2, O_RDWR | O_CREAT | O_TRUNC , S_IRUSR | S_IWUSR);
    if(fdi < 0)
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on creating sideblock '%s' errno: %d\n", ptmp2, errno);

        // Not sure what to do ... error?
        ret = -errno;
        goto endd3;
        }
    int ww = write(fdi, psb, sizeof(sideblock_t));
    if(ww < sizeof(sideblock_t))
        {
        if (loglevel > 0)
            syslog(LOG_DEBUG, "Error on writing to sideblock errno: %d\n", errno);
        }
    close(fdi);
    errno = old_errno;

  endd3:
    free(psb);

  endd2:
    free(ptmp2);

   endd:
    return ret;
}

void    kill_sideblock(sideblock_t *psb)

{
    if(psb)
        kill_buff(psb, sizeof(psb));
}

// EOF