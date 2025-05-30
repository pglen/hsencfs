#define _GNU_SOURCE

#include <ulockmgr.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <libgen.h>
#include <sys/time.h>

#include <signal.h>
#include <getopt.h>

int loglevel = 10;

void    hslog(int lev, char *fmt, ...)

{

    if (loglevel > lev)
        {
        va_list ap;
        va_start(ap, fmt);
        //vsyslog(LOG_DEBUG, fmt, ap);
        vprintf(fmt, ap);
        printf("\n");
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

void parse_comstr(char *argx[], int limx, char *program)

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

// -----------------------------------------------------------------------

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
        printf("Unable to create pipe.");
        //perror("Unable to create pipe");
        //return("");
        }
    if ((pid = fork()) == -1)
        {
        hslog(0, "Unable to dup2");
        printf("Unable to dup2");
        // perror("Unable to fork");
        return("");
        }
    if (pid == 0) {
    	   /* child, point stdout to output side of the pipe and exec askpass */
    	//if (dup2(pfd[1], STDOUT_FILENO) == -1) {
        //           hslog(0, "Unable to dup2");
        //           //printf("Unable to dup2");
        //           //_exit(255);
        //           //return("");
    	//       }
        hslog(0, "pid4");
        //(void) dup2(pfd[1], STDOUT_FILENO);
        // Redirect error messages:
        int fh = open("/dev/null", O_RDWR );
    	(void) dup2(fh, STDERR_FILENO);
        hslog(0, "pid5");

    	//set_perms(PERM_FULL_USER); //TODO
    	closefrom(STDERR_FILENO + 1);

        char *argx[12] ;
        hslog(0, "ppp %s", program);
        parse_comstr(argx, 12, program);

        int xx = 0;
        while(1)
            {
            printf("ptr: '%s'\n", argx[xx]);
            if(!argx[xx])
                break;
            xx++;
            }
    	execvp(argx[0], argx);

    	//execl(program, (char *)NULL);
        hslog(LOG_DEBUG, "Unable to run askpass: '%s'", program);
        //printf("Unable to run %s", program);

        // Try fallback:
        //char *fallback = "xfce4-terminal -e hsaskpass.sh";
        //execl(fallback, fallback, NULL);
    	//hslog(LOG_DEBUG, "Unable to run2 askpass: '%s'", fallback);
        //printf("Unable to run2 %s", fallback);

        //_exit(255);
        return("");
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

char buf[PATH_MAX];

int     main(int argc, char *argv[])

{
    //char *pass = hs_askpass("../hsaskpass.pyc", buf, sizeof(buf));
    //printf("pass %s\n", pass) ;
    char *pass2 = hs_askpass("xfce4-terminal -e ../hsaskpass.sh", buf, sizeof(buf));
    //printf("pass2 %s\n", pass2) ;
}
