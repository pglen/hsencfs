/*
 *   High security encryption file system. Password routines.
 */

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
#include <syslog.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <getopt.h>

#include "hsutils.h"
#include "../bluepoint/bluepoint2.h"

extern char    progname[];
extern int     loglevel;

#define MARK_SIZE 1024

// Create mark file. Random block, one half is encrypted with the
// password and saved to the other half. Checking is done by
// decrypting the second half, comparing it to the first.

static int create_markfile(char *name, char *pass, int *plen)

{
    int loop, ret = 0;
    char *ttt = malloc(MARK_SIZE);
    if(!ttt)
        return -errno;
    char *ttt2 = malloc(MARK_SIZE / 2);
    if(!ttt2)
        { free(ttt); return -errno; }

    srand(time(NULL));

    // Generate crap
    for(loop = 0; loop < MARK_SIZE; loop++)
        { ttt[loop] = rand() % 0xff; }

    // Verify:
    //for(loop = 0; loop < 30; loop++)
    //    printf("%x ", ttt[loop] & 0xff);

    memcpy(ttt2, ttt, MARK_SIZE / 2);
    bluepoint2_encrypt(ttt2, MARK_SIZE / 2, pass, *plen);
    memcpy(ttt + MARK_SIZE / 2, ttt2, MARK_SIZE / 2);
    if (ttt2) free(ttt2);

    //int fh = open(name, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    int fh = open(name, O_CREAT | O_WRONLY, S_IRUSR);
    if(fh < 1)
        { if(ttt) free(ttt); return -errno;}

    if (write(fh, ttt, MARK_SIZE) != MARK_SIZE)
        { if(ttt) free(ttt); close(fh); return -errno; }

    close(fh);

    if (ttt) free(ttt);

    return ret;
}

// See notes on create_markfile

static int check_markfile(char *name, char *pass, int *plen)

{
    int ret = 0;

    // Checking
    char *ttt = malloc(MARK_SIZE);
    if(!ttt)
        return -errno;

    int fh = open(name, O_RDONLY);
    if(fh < 1)
        { if(ttt) free(ttt); return -errno; }

    if (read(fh, ttt, MARK_SIZE) != MARK_SIZE)
        {
        if(ttt) free(ttt); close(fh); return -errno;
        }

    close(fh);

    bluepoint2_decrypt(ttt + MARK_SIZE / 2, MARK_SIZE / 2, pass, *plen);
    ret = memcmp(ttt, ttt + MARK_SIZE / 2, MARK_SIZE / 2);

    if(ttt) free(ttt);

    return ret;
}

#if 0

// -----------------------------------------------------------------------
// Just for checking, do not use in production code.

static  void printpass(char *pp, int ll)
{
    char *ttt = malloc(ll);
    if(ttt)
        {
        memcpy(ttt, pp, ll); ttt[ll] = 0;
        bluepoint2_decrypt(ttt, ll, progname, strlen(progname));
        //printf("got pass '%s'\n", ttt);
        // Erase it by encrypt / clear
        bluepoint2_encrypt(ttt, ll, progname, strlen(progname));
        memset(ttt, 0, ll);
        free(ttt);
        }
}

#endif

// Get the password for the current mount or create a new one.
// Return 0 if all OK.

int pass_ritual(char *mountroot, char *mountdata, char *pass, int *plen)

{
    int ret = -1, pask = 0, xlen2 = 0, xlen = strlen(pass);
    char *xpass2 = NULL, *xpass = NULL;
    struct stat ss;   char tmp[PATH_MAX];

    pask = (xlen == 0) ? 1 : 0;
    if(pask)
        {
        sprintf(tmp,    "\n"
                        "About to mount: '%s'\n"
                        "Data directory: '%s'\n"
                        "Entering empty password (pressing Return) will Abort.\n"
                        "\n"
                        "Please enter HSENCFS pass: ", mountroot, mountdata);
        xpass = getpass(tmp);  //printf("password: '%s'\n", pass);
        xlen = strlen(xpass);
        if(xlen == 0)
            {
            fprintf(stderr, "Aborted.\n");
            if(loglevel > 0)
               syslog(LOG_DEBUG, "Aborted pass entry by uid: %d\n", getuid());
            return 1;
            }
        // Dup the results right away, clear it too
        strncpy(pass, xpass, *plen);
        memset(xpass, 0, xlen);
        }

    // Always padd it
    if(xlen % 2)
        strncat(pass, "x", sizeof(pass));

    // Encrypt the results right away
    *plen = strlen(pass);
    bluepoint2_encrypt(pass, *plen, progname, strlen(progname));

    //printpass(pass, *plen);

    // Check it against saved pass, warn if creating new mount
    char tmp2[PATH_MAX];
    strncpy(tmp2, mountdata, sizeof(tmp)); strcat(tmp2, ".passdata");
    if(stat(tmp2, &ss) < 0)
        {
        if(pask)
            {
            sprintf(tmp,    "\n"
                            "This is a new mount with no password set.\n"
                            "\n"
                            "Please re-enter HSENCFS pass: ");

            xpass2 = getpass(tmp);
            xlen2 = strlen(xpass2);
            if(xlen2 == 0)
                {
                fprintf(stderr, "Aborted.\n");
                return ret;
                }
            // Always padd it
            if(xlen2 % 2)
                strcat(xpass2, "x");
            xlen2 = strlen(xpass2);
            bluepoint2_encrypt(xpass2, xlen2, progname, strlen(progname));

            //printpass(xpass2, xlen2);

            if (memcmp(pass, xpass2, *plen))
                {
                memset(xpass2, 0, xlen2);
                fprintf(stderr, "Passes do not match. Aborted\n");
                if(loglevel > 0)
                    syslog(LOG_DEBUG, "Passes do not match by uid: %d\n", getuid());
                return ret;
                }
            memset(xpass2, 0, xlen2);
            }
        ret = create_markfile(tmp2, pass, plen);
        if (ret)
            fprintf(stderr,"Error on creating markfile.\n");
        }
    else
        {
        ret = check_markfile(tmp2, pass, plen);

        if (ret)
            {
            fprintf(stderr, "Invalid pass.\n");

            if(loglevel > 0)
                syslog(LOG_DEBUG, "Invalid pass entered by uid: %d\n", getuid());
            }

        //printf("Checking '%s' got %d", tmp2, ret);
        }

    return ret;
}











