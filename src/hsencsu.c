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

#include "hsencsb.h"
#include "hsencfs.h"

#include "../bluepoint/hs_crypt.h"
#include "../bluepoint/bluepoint2.h"
#include "../common/hsutils.h"

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
// Read a line from the forked program

static char  *getlinex(int fd, char *buf, size_t bufsiz)

{
    size_t left = bufsiz;
    ssize_t nr = -1;
    char *cp = buf; char c = '\0';

    if (left == 0) {
    	errno = EINVAL;
    	return(NULL);			/* sanity */
    }

    while (--left) {
	   nr = read(fd, &c, 1);
    	if (nr != 1 || c == '\n' || c == '\r')
    	    break;
	   *cp++ = c;
    }
    *cp = '\0';

    return(nr == 1 ? buf : NULL);
}

// Really dumb parse command line to array

void parse_comstr(char *argx[], int limx, const char *program)

{
    //printf("parse: '%s'\n", program);

    // Parse command line
    char aa = 0, bb = 0, cc = 0;
    argx[cc] = NULL;
    char curr[128];
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
        else if (chh == ' ')
            {
            //printf("str: '%s'\n", curr);
            if (curr[0] == '\0')
                {
                aa++;
                continue;
                }
            argx[cc] = strdup(curr);
            cc++; bb = 0;
            curr[bb] = '\0';
            }
        else
            {
            curr[bb] = chh;
            bb++;
            curr[bb] = '\0';
            }
        aa++;
        }
}


/*
 * Fork a child and exec progran to get the password from the user.
 */

char *hs_askpass(const char *program, char *buf, int buflen)

{
    struct sigaction  sa, saved_sa_pipe;
    int pfd[2];  pid_t pid;

    //char cwd[PATH_MAX];

    hslog(0, "Asking pass with program: '%s'", program);
    //hslog(0, "Asking pass in '%s'", getcwd(cwd, sizeof(cwd)));

    if (pipe(pfd) == -1)
	   {
        hslog(0, "Unable to create pipe.");
        //printf("Unable to create pipe.");
        //perror("Unable to create pipe");
        //return("");
        }
    if ((pid = fork()) == -1)
        {
        hslog(0, "Unable to fork");
        //printf("Unable to dup2");
        // perror("Unable to fork");
        return(NULL);
        }
    if (pid == 0) {
    	/* child, point stdout to output side of the pipe and exec askpass */
    	if (dup2(pfd[1], STDOUT_FILENO) == -1) {
                hslog(0, "Unable to dup2");
                //printf("Unable to dup2");
                //_exit(255);
                return("");
    	       }
        (void) dup2(pfd[1], STDOUT_FILENO);
        // Redirect error messages:
        int fh = open("/dev/null", O_RDWR );
    	(void) dup2(fh, STDERR_FILENO);

    	//set_perms(PERM_FULL_USER); //TODO
    	closefrom(STDERR_FILENO + 1);

        char *argx[12];
        parse_comstr(argx, 12, program);
        int xx = 0; while(1)
            {
            //hslog(0, "ptr: '%s'\n", argx[xx]);
            if(!argx[xx])
                break;
            xx++;
            }

        execvp(argx[0], argx) ;
        parse_comstr(argx, 12, program);
        xx = 0; while(1)
            {
            if(!argx[xx])
                break;
            free(argx[xx]);
            xx++;
            }
        hslog(0, "Unable to run askpass: '%s'", program);
        //printf("Unable to run %s", program);
        // Try fallback:
        //char *fallback = "xfce4-terminal -e hsaskpass.sh";
        //execl(fallback, fallback, NULL);
    	//hslog(LOG_DEBUG, "Unable to run2 askpass: '%s'", fallback);
        //printf("Unable to run2 %s", fallback);
        //_exit(255);
        return(NULL);
        }

    /* Ignore SIGPIPE in case child exits prematurely */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGPIPE, &sa, &saved_sa_pipe);

    /* Get response from child and restore SIGPIPE handler */
    (void) close(pfd[1]);

    char *xpass = getlinex(pfd[0], buf, buflen);
    (void) close(pfd[0]);
    (void) sigaction(SIGPIPE, &saved_sa_pipe, NULL);

    return(xpass);
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
    // Error ?
     if (res == NULL)
        {
        hslog(0, "Cannot get pass for '%s' with %s\n", path, passprog);
        return 1;
        }
    // Do not debug sensitive data
    //hslog(0, "Askpass delivered: '%s'\n", res);

    int rlen = strlen(res);
    // Empty pass ?
    if(rlen == 0)
        {
        hslog(2, "Aborted on empty pass from: '%s'\n", passprog);
        return 1;
        }
    // Decode base64
    unsigned long olen = 0;
    unsigned char *res2 = base64_decode(res, rlen, &olen);
    strncpy(passx, res2, sizeof(passx));
    plen = strlen(passx);

    // Do not debug sensitive data
    //hslog(2, "passx '%s'\n", passx);

    int ret2 = pass_ritual(mountpoint, mountsecret, passx, &plen);
    if(ret2)
        {
        // Force new pass prompt
        memset(passx, 0, sizeof(passx));
        hslog(-1, "Invalid pass for '%s' by uid: %d\n", mountpoint, getuid());
        return ret2;
        }
    return ret;
}

// EOF