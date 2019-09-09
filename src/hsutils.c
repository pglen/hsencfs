/*
 *  High security encryption file system. We make use of the API offered by
 *  the fuse subsystem to intercept file operations.
 */

#define FUSE_USE_VERSION 26

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
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

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

// Simple help

int help()

{
    printf("\n");
    printf("Usage: hsencfs [options] storagedir mountpoint\n");
    printf("\n");
    printf("Where 'storageedir' is a storage directory for data and ");
    printf("'mountpoint' is a directory for user visible data. ");
    printf("Use dotted name as storagedir for convenient hiding  of data names. ");
    printf(" (ex: ~/.secretdata)\n");
    printf("Options:        -l num      -- Use log level  (--loglevel)\n");
    printf("                -p pass     -- Use pass (!!Warning!! cleartext pass) (--pass)\n");
    printf("                -a program  -- Use program for asking pass (--askpass)\n");
    printf("                -o          -- On demand pass. Ask on first access (--ondemand)\n");
    printf("                -f          -- Force creation of storagedir/mountpoint (--force)\n");
    printf("                -q          -- Quiet (--quiet)\n");
    printf("                -v          -- Verbose (--verbose)\n");
    printf("                -V          -- Print version (--version)\n");
    printf("Log levels:      1 - start/stop;   2 - open/create\n");
    printf("                 3 - read/write;   4 - all (noisy)\n");
    printf("Use '--' to at the end of options for appending fuse options. ");
    printf("For example: 'hsencfs sdata mpoint -- -o ro' for read only mount.\n");
    printf("Typical invocation: \n");
    printf("    hsencfs -l 2  ~/.secretdata ~/secret\n");
}














