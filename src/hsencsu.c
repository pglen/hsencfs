// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//
// Extracted for eazy editing. This code took forever.
//
// Supporting utilities
//
// -----------------------------------------------------------------------
// Shorthand for log to syslog

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

#include "hsencfs.h"
#include "base64.h"
#include "hsencsb.h"
#include "hs_crypt.h"
#include "bluepoint2.h"
#include "hsutils.h"
#include "hspass.h"

// -----------------------------------------------------------------------
// Check if it is our internal file

int     is_our_file(const char *path, int fname_only)

{
    int ret = FALSE;
    char *eee = "/.";
    if(fname_only == FALSE)
        {
        eee = strrchr(path, '/');
        }
    char *nnn = strrchr(path, '.');

    // Determine if it is our data file, deny access
    if(eee && nnn)
        {
        if(eee[1] == '.' && strncmp(nnn, myext, sizeof(myext) - 1) == 0 )
            {
            ret = TRUE;
            }

        //if (loglevel > 4)
        //    syslog(LOG_DEBUG, "is_our_file: eee '%s' nnn '%s' ret=%d\n", eee, nnn, ret);
        }
    return ret;
}

// Estabilish file size

off_t    get_fsize(int fh)

{
    struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    fstat(fh, &stbuf);
    return stbuf.st_size;
}

char    *alloc_path2(const char *path)

{
    char  *path2 = malloc(PATH_MAX);
    if(path2)
        {
        memset(path2, '\0', PATH_MAX);
        strcpy(path2, mountsecret);
        //if(path[0] == '/')
        //    strcat(path2, path + 1);
        //else
            strcat(path2, path);
        }
    return path2;
}

// -----------------------------------------------------------------------
// Encrypt (double decrypt) it: This is a fake encryption of the
// dangling memory, Just to confuse the would be decoder

void  kill_buff(void *bbuff, int xlen)

{
    // Do not leave data behind
    if (bbuff)
        {
        #if 1
        // Just to confuse the would be debugger
        if(rand() % 2 == 0)
            hs_decrypt(bbuff, xlen, "passpass", 8);
        else
            hs_decrypt(bbuff, xlen, "pass", 4);

        // No data left behind
        memset(bbuff, 0, xlen);        // Zero it
        #endif

        free(bbuff);
        }
}

// -----------------------------------------------------------------------
// Go through pass ritual on demand

int     openpass(const char *path)

{
    int ret = 0;

    hslog(3, "Openpass() path: '%s'", path);

    if(defpassx[0] != '\0')
        {
        hslog(-1, "Using default pass '%s'", defpassx);
        return 0;
        }

    char tmp[MAXPASSLEN];
    char *tmp2 = malloc(PATH_MAX + PATH_MAX + 12);
    if (!tmp2)
        {
        ret = 1;
        goto endx2;
        }
    if(passprog[0] == 0)
        {
        hslog(-1, "No pass program specified: %s uid: %d\n", path, getuid());
        ret = 1;
        goto endx;
        }
    char tmp3[PATH_MAX + PATH_MAX +  2];
    strncpy(tmp3, mountsecret, sizeof(tmp3));
    strcat(tmp3, passfname);
    //printf("tmp3: '%s'\n", tmp3);
    struct stat ss;
    int rret = stat(tmp3, &ss);

    snprintf(tmp2, PATH_MAX + PATH_MAX + 12, "%s %s %d",
                                      passprog, mountpoint, rret);
    //ret = hs_askpass(tmp2, tmp, MAXPASSLEN);
    // Error ?
     if (ret != 0)
        {
        hslog(0, "Cannot get pass for '%s' with %s\n", path, passprog);
        ret = 1;
        goto endx;
        }
    // Do not debug sensitive data
    //hslog(0, "Askpass delivered: '%s'\n", res);
    int rlen = strlen(tmp);
    // Empty pass ?
    if(rlen == 0)
        {
        hslog(2, "Aborted on empty pass from: '%s'\n", passprog);
        ret = 1;
        goto endx;
        }
    // Decode base64
    unsigned long olen = 0;
    unsigned char *res2 = base64_decode(tmp, rlen, &olen);
    //defplen = strlen(defpassx);
    //strncpy(passx, res2, sizeof(passx));
    if(res2)
        {
        strcpy(defpassx, res2);
        free(res2);
        }
    // Do not log sensitive data
    //hslog(2, "passx '%s'\n", passx);

    //int ret2 = pass_ritual(mountpoint, mountsecret, passx, &defplen, passprog);
    //if(ret2)
    //    {
    //    // Force new pass prompt
    //    memset(passx, 0, sizeof(passx));
    //    hslog(-1, "Invalid pass for '%s' by uid: %d\n", mountpoint, getuid());
    //    ret =  ret2;
    //    goto endx;
    //    }

  endx:
    if(tmp2)
        free(tmp2);
   endx2:
    return ret;
}

// EOF