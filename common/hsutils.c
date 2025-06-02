/*
 *  High security encryption file system. We make use of the API offered by
 *  the fuse subsystem to intercept file operations.
 */

//#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <fuse.h>
#include <ulockmgr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>
#include <syslog.h>
#include <mntent.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "../src/hsencfs.h"
#include "hsutils.h"

// See if it is mounted already

int     ismounted(char *orig)

{
    int ret = 0;

    char *ddd = strdup(orig);
    if (!ddd) return 0;
    int xlen = strlen(ddd);
    // Trailaing slash?
    if(ddd[xlen-1] == '/')
       ddd[xlen-1] = '\0';

     FILE *fp;
     struct mntent *mnt;

     fp = setmntent("/proc/mounts", "r"); // Or "/etc/mtab"
     if (fp == NULL) {
         //perror("setmntent");
         return 0;
     }

     while ((mnt = getmntent(fp)) != NULL) {
         //printf("'%s' -> '%s'\n", mnt->mnt_dir, ddd);
         if(strcmp(ddd, mnt->mnt_dir) == 0)
            {
            ret = 1;
            break;
            }
        }
    endmntent(fp);
    free(ddd);
    return ret;
}

int     countfiles(char *mpoint)

{
    int cnt = 0;

    DIR *dd; struct dirent *dir;
    dd = opendir(mpoint);
    if (!dd)
        {
        //fprintf(stderr,"Cannnot open MountPoint directory\n");
        //exit(5);
        return -1;
        }
    // See how many files are in there ... count up to 4
    for (int aa = 0; aa < 4; aa++)
        {
        if((dir = readdir(dd)) == NULL)
            break;
        cnt++;
        }
    closedir(dd);

    return cnt;
}

void    hsprint(int outs, int lev, char *fmt, ...)

{
    if (outs & TO_OUT)
        {
        if (loglevel > lev || lev == -1)
            {
            va_list ap; va_start(ap, fmt);
            vfprintf(stdout, fmt, ap);
            va_end(ap);
            }
        }
    if (outs & TO_ERR)
        {
        if (loglevel > lev || lev == -1)
            {
            va_list ap; va_start(ap, fmt);
            vfprintf(stderr, fmt, ap);
            va_end(ap);
            }
        }
    if (outs & TO_LOG)
        {
        if (loglevel > lev || lev == -1)
            {
            va_list ap; va_start(ap, fmt);
            vsyslog(LOG_DEBUG, fmt, ap);
            va_end(ap);
            }
        }
}

void    hslog(int lev, char *fmt, ...)

{
    if (loglevel > lev || lev == -1)
        {
        va_list ap; va_start(ap, fmt);
        vsyslog(LOG_DEBUG, fmt, ap);
        va_end(ap);
        }
}

// -----------------------------------------------------------------------
// Expand path for home / abs / rel.
// The shell does it, but we make sure too, just in case it is called
// from a another program.

void    expandpath(const char *inp, char *outp, int maxlen)

{
    if(inp[0] == '/')                           // Absolute
        {
        strncpy(outp, inp, maxlen);
        }
    else if(inp[0] == '~' && inp[1] == '/')     // Home Relative
        {
        char *env = getenv("HOME");
        strcpy(outp, env);
        if(outp[strlen(outp)-1] != '/')
            strcat(outp, "/");
        strcat(outp, inp + 2);
        }
    else                                        // Relative
        {
        char  tmp_path[PATH_MAX] ;
        char *ppp = getcwd(tmp_path, sizeof(tmp_path));
        (void)ppp;
        strcpy(outp, tmp_path);  strcat(outp, "/"); strcat(outp, inp);
        }
}

// EOF
