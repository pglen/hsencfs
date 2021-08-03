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

#include "base64.h"

#include "../bluepoint/hs_crypt.h"
#include "../bluepoint/bluepoint2.h"
#include "../common/hsutils.h"

#include "hsencfs.h"

void    hslog(int lev, char *fmt, ...)

{
    if (loglevel > lev)
        {
        va_list ap;
        va_start(ap, fmt);
        vsyslog(LOG_DEBUG, fmt, ap);
        va_end(ap);
        }
}

// -----------------------------------------------------------------------
// Scratch pad for the whole lot

void    *hsalloc(int total)

{
    void *mem =  malloc(total);
    if (mem == NULL)
        {
        hslog(0, "Cannot get main block memory.\n");
        goto endd;
        }
     memset(mem, '\0', total);                  // Zero it

 endd:
    return mem;
}

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
    char tmp[MAXPASSLEN];
    int ret = 0;

    if(passprog[0] == 0)
        {
        if (loglevel > 1)
            syslog(LOG_DEBUG, "No pass program specified: %s uid: %d\n", path, getuid());
        return 1;
        }
    char *res = hs_askpass(passprog, tmp, MAXPASSLEN);
    if (res == NULL || strlen(res) == 0)
        {
        if (loglevel > 1)
            syslog(LOG_DEBUG, "Cannot get pass for %s uid: %d\n", path, getuid());
        return 1;
        }

    strncpy(passx, res, sizeof(passx));

    int ret2 = pass_ritual(mountpoint, mountsecret, passx, &plen);
    if(ret2)
        {
        // Force new pass prompt
        memset(passx, 0, sizeof(passx));
        if (loglevel > 1)
            syslog(LOG_DEBUG, "Invalid pass for %s uid: %d\n", path, getuid());
        return ret2;
        }
    return ret;
}

// EOF