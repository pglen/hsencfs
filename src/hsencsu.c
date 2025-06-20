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

#include "hsencdef.h"
#include "hsencfs.h"
#include "hsutils.h"
#include "hspass.h"
#include "hsutils.h"
#include "xmalloc.h"
#include "base64.h"
#include "hsencsb.h"
#include "hs_crypt.h"
#include "bluepoint2.h"

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
        if(path[0] == '/')
            strcat(path2, path + 1);
        else
            strcat(path2, path);
        }
    return path2;
}

// -----------------------------------------------------------------------
// Go through pass ritual on demand

int     openpass(const char *path)

{
    int pret = 0;
    hslog(3, "Openpass() path: '%s'", path);
    if(gotdefpass)
        {
        hslog(1, "Using default pass '%s'", defpassx);
        return 0;
        }
    if(passprog[0] == 0)
        {
        hslog(1, "No pass program specified: '%s'\n", path);
        pret = 1;
        goto endx;
        }
    PassArg passarg;
    passarg.result = xmalloc(MAXPASSLEN);
    if (!passarg.result)
        {
        hslog(1, "openpass() cannot alloc tmp: '%s'\n", path);
        pret = 1; goto endx;
        }
    memset(passarg.result, '\0', MAXPASSLEN);
    if (access(markfile, R_OK) < 0)
        passarg.create = 1;
    else
        passarg.create = 0;
    passarg.prompt = "\'  Enter pass:  \'",
    passarg.title = mountpoint;
    passarg.gui = 1;
    passarg.passprog = passprog;
    passarg.mountstr = (char *)path;
    passarg.markfname = markfile;
    passarg.reslen = MAXPASSLEN;
    pret = getpass_front(&passarg);
    if(pret == HSPASS_OK)
        {
        //printf("passarg res: '%s'\n", passarg.result);
        memcpy(defpassx, passarg.result, MAXPASSLEN);
        }
    else
        {
        // Error ?
        hslog(3, "Cannot get pass for '%s' with %s\n", path, passprog);
        pret = 1; //EKEYREJECTED;
        memset(defpassx, '\0', sizeof(defpassx));
        gotdefpass = FALSE;
        }
   endx:
    return pret;
}

// EOF