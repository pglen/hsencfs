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
#include <stdarg.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "hsencfs.h"
#include "hsutils.h"

int loglevel = 1;

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
    //printf("Logging loglevel=%d lev=%d\n", loglevel, lev);

   if(loglevel == 0)
        return;

     if (lev <= loglevel)
        {
        if (outs & TO_OUT)
            {
            va_list ap; va_start(ap, fmt);
            vfprintf(stdout, fmt, ap);
            va_end(ap);
            fprintf(stdout, "\n");
            }
        if (outs & TO_ERR)
            {
            va_list ap; va_start(ap, fmt);
            vfprintf(stderr, fmt, ap);
            va_end(ap);
            fprintf(stderr, "\n");
            }
        if (outs & TO_LOG)
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

void    hsfree(void *mem, int size)

{
    if (!mem)
        {
        printf("Warn: free null\n");
        return;
        }
    char *ptr = (char *)mem;
    for(int aa = 0; aa < size; aa++)
        {
        ptr[aa] = (char)(rand() & 0xff);
        }
    free(mem);
}

char    *hexdump(char *ptr, int len)

{
    //printf("len=%d  '%s'\n", len, ptr);
    char *pret = xmalloc(len * 5);
    //memset(pret, '\0', len * 5);

    int prog = 0, llen = 24, plen = 0;
    for (int aa = 0; aa < len; aa++)
        {
        uchar chh = ptr[aa] & 0xff;
        //printf("%c", chh);
        if(chh > 127 || chh < 32)
            plen = sprintf(pret + prog, "%.2x ", chh);
        else
            plen = sprintf(pret + prog, " %c ", chh);
        prog += plen;
        if (aa % llen == llen-1)
            {
            plen = sprintf(pret + prog, "\n");
            prog += plen;
            }
        }
    return(pret);
}

void    arr2log(char *argx[])

{
    int xx = 0;
    while(1)
        {
        hsprint(TO_ERR | TO_LOG, 3,
            "argx[%d] ptr: '%s'\n", xx, argx[xx]);
        if(!argx[xx++])
            break;
        }
    hsprint(TO_ERR | TO_LOG, 3, "\n");
}

// Really dumb parse command line to array

int     parse_comstr(char *argx[], int limx, const char *program)

{
    //printf("parse: '%s'\n", program);

    // Parse command line
    char aa = 0, bb = 0, cc = 0;
    argx[cc] = NULL;
    char curr[128];
    int in_quote = FALSE;
    int in_squote = FALSE;

    while(1)
        {
        char chh = program[aa];
        //printf("%c", chh);
        if(cc >= limx-1)
            {
            //printf("Warn: argx limit %d\n", cc);
            argx[cc] = NULL;
            break;
            }
        if (chh == '\0')
            {
            //printf("estr: '%s'\n", curr);
            if (curr[0] != '\0')
                {
                argx[cc] = strdup(curr);
                cc++;
                }
            argx[cc] = NULL;
            break;
            }
        else if (chh == '\'')
            {
            if (in_quote)
                goto just_char;
            else
                if (in_squote)
                    in_squote = 0;
                else
                    in_squote = 1;
            }
        else if (chh == '\"')
            {
            if (in_squote)
                goto just_char;
            else
                 if (in_quote)
                    in_quote = 0;
                else
                    in_quote = 1;
            }
        else if (chh == ' ')
            {
            //printf("str: '%s'\n", curr);
            if (curr[0] == '\0')
                {
                aa++;
                continue;
                }
            if(in_quote)
                goto just_char;
            if(in_squote)
                goto just_char;

            argx[cc] = strdup(curr);
            cc++; bb = 0;
            curr[bb] = '\0';
            }
        else
            {
          just_char:
            curr[bb] = chh;
            bb++;
            curr[bb] = '\0';
            }
        aa++;
        }
    return cc;
}

Malloc_Store malloc_store = {0, 0, NULL };
static  int malloc_step = 100;
int  malloc_verbose = 0;

void    *xmalloc(int size)

{
    char *ptr = malloc(size);

    if(ptr)
        {
        if(malloc_verbose > 0)
            printf("xmalloc: %d %p\n", size, ptr);

        if(malloc_store.curr >= malloc_store.size)
            {
            // Realloc
            int newsize = malloc_store.size + malloc_step;
            if(malloc_verbose > 1)
                printf("realloc at %d\n", newsize);
            malloc_store.store = realloc(malloc_store.store,
                                        sizeof(Malloc) * newsize);
            malloc_store.size = newsize;
            }
        malloc_store.store[malloc_store.curr].ptr = ptr;
        malloc_store.store[malloc_store.curr].size = size;
        malloc_store.store[malloc_store.curr].freed = 0;

        malloc_store.curr++;
        }
    return ptr;
}

void    xmdump(int level)

{
    for(int aa = 0; aa <  malloc_store.curr; aa++)
        {
        if(level)
            {
            printf("ptr: %p size: %d freed: %d\n",
                    malloc_store.store[aa].ptr,
                            malloc_store.store[aa].size,
                                malloc_store.store[aa].freed);
            }
        else
            {
            if(!malloc_store.store[aa].freed)
                printf("ptr: %p size: %d freed: %d\n",
                    malloc_store.store[aa].ptr,
                            malloc_store.store[aa].size,
                                malloc_store.store[aa].freed);
            }
        }
}

void    xsfree(void *ptr)
{
    // safe free
    int found = -1;
    for(int aa = 0; aa <  malloc_store.curr; aa++)
        {
        if(malloc_store.store[aa].ptr == ptr)
            {
            found = aa;
            }
       }
    if (found < 0)
        {
        if(malloc_verbose > 0)
            printf("Error on xfree: %p\n", ptr);
        }
    else
        {
        //printf("xsfree: %d\n", malloc_store.store[found].size );
        for(int bb = 0; bb < malloc_store.store[found].size; bb++)
            {
            ((char *)ptr)[bb] = rand() & 0xff;
            }
        malloc_store.store[found].freed = 1;
        }
    free(ptr);
}

void    xfree(void *ptr)

{
    if(malloc_verbose > 1)
        printf("freeing %p ... ", ptr);

    int found = -1;
    for(int aa = 0; aa <  malloc_store.curr; aa++)
        {
        if(malloc_store.store[aa].ptr == ptr)
            {
            if(malloc_verbose > 3)
                printf("ptr: %p size: %d freed: %d\n",
                    malloc_store.store[aa].ptr,
                             malloc_store.store[aa].size,
                                malloc_store.store[aa].freed);
            found = aa;
            }
        }
    if (found < 0)
        {
        if(malloc_verbose > 2)
            printf("Error on xfree: %p\n", ptr);
        }
    else
        {
        malloc_store.store[found].freed = 1;
        }
    free(ptr);
}

// EOF
