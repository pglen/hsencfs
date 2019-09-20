/*
 * HSENCFS (High Security EnCrypting File System)
 *
 * High security encryption file system. We make use of the API offered by
 * the fuse subsystem to intercept file operations.
 *
 * The interception is done between mountdata and mountpoint. Copying data
 * to mountpoint ends up encrypted in mountdata. Copying data from mountpoint
 * is sourced from mountdata and decrypted. See "hsencrw.c".
 *
 * Use a dotted file for mountdata (like .data or .secretdata)
 *
 * One additional useful feature is auditing. Reports file access by user ID.
 * The report is sent to syslog. (use the -l option to turn on log)
 *
 * To make it:
 *
 *     gcc -lfuse -lulockmgr [localobjects ...] hsencfs.c -o hsencfs
 *
 *  To use it:
 *
 *       hsenc [-f] ~/.secretdata ~/secrets
 *
 *  Command above will expose the ~/secrets directory. It is sourced from the
 *  backing directory ~/.secretdata
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

#include "hsutils.h"
#include "base64.h"
#include "../bluepoint/bluepoint2.h"

#define MAXPASSLEN 512

// Log
static FILE *logfp = NULL;

// Flags
static  int     verbose = 0;
static  int     quiet = 0;
static  int     force = 0;
static  int     ondemand = 0;

// Shared flags
int     loglevel = 0;

// Maintain internal count
static  char    version[] = "1.17";

// The decoy employed occasionally to stop spyers
// from figuring out where it is stored

static  char    passx[MAXPASSLEN];
static  int     plen = sizeof(passx);
static  char    decoy[MAXPASSLEN];
static  int     plen2 = sizeof(decoy);

// Main directories for data / encryption

static  char  mountpoint[PATH_MAX] ;
static  char  mountdata[PATH_MAX] ;
static  char  passprog[PATH_MAX] ;

static  char  inodedir[PATH_MAX] ;

/// We use this as a string to obfuscate the password. Do not change.
char    progname[] = "HSENCFS";

// Get the extracted sources:
#include "hsencrw.c"
#include "hsencop.c"

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.fgetattr	= xmp_fgetattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.opendir	= xmp_opendir,
	.readdir	= xmp_readdir,
	.releasedir	= xmp_releasedir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.ftruncate	= xmp_ftruncate,
	.utimens	= xmp_utimens,
	.create		= xmp_create,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.flush		= xmp_flush,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
	.lock		= xmp_lock,

	.flag_nullpath_ok = 1,
};

// Use /proc/self/fd directory to close fd-s

void    closefrom(int lowfd)

{
    struct dirent *dent;  DIR *dirp;
    char *endp;  long fd;

    if ((dirp = opendir("/proc/self/fd")) != NULL) {
	   while ((dent = readdir(dirp)) != NULL) {
	   fd = strtol(dent->d_name, &endp, 10);
	    if (dent->d_name != endp && *endp == '\0' &&
		  fd >= 0 && fd < INT_MAX && fd >= lowfd && fd != dirfd(dirp))
            {
            (void) close((int) fd);
            }
	   }
	   (void) closedir(dirp);
    }
}

// Read a line from the forked program

static char *getln(int fd, char *buf, size_t bufsiz)

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

/*
 * Fork a child and exec progran to get the password from the user.
 */

char *hs_askpass(const char *program, char *buf, int buflen)

{
    struct sigaction  sa, saved_sa_pipe;
    int pfd[2];   pid_t pid;

    if (pipe(pfd) == -1)
	   perror("Unable to create pipe");

	   //perror(1, "Unable to create pipe");

    if ((pid = fork()) == -1)
	   perror("Unable to fork");

        //error(1, "Unable to fork");

    if (pid == 0) {
    	/* child, point stdout to output side of the pipe and exec askpass */
    	if (dup2(pfd[1], STDOUT_FILENO) == -1) {
    	    printf("Unable to dup2");
    	    _exit(255);
    	   }
    	(void) dup2(pfd[1], STDOUT_FILENO);
        // Redirect error messages:
        int fh = open("/dev/null", O_RDWR );
    	(void) dup2(fh, STDERR_FILENO);

    	//set_perms(PERM_FULL_USER); //TODO
    	closefrom(STDERR_FILENO + 1);
    	execl(program, program, NULL);
    	//execl(program, (char *)NULL);
    	printf("Unable to run %s", program);
    	_exit(255);
        }

    /* Ignore SIGPIPE in case child exits prematurely */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGPIPE, &sa, &saved_sa_pipe);

    /* Get response from child and restore SIGPIPE handler */
    (void) close(pfd[1]);

    char *xpass = getln(pfd[0], buf, buflen);
    (void) close(pfd[0]);
    (void) sigaction(SIGPIPE, &saved_sa_pipe, NULL);

    // Decode base64
    return(xpass);
}

// -----------------------------------------------------------------------
// Process command line options, set up for mount.

static struct option long_options[] =
    {
        {"loglevel",    1,  0,  'l'},
        {"help",        0,  0,  'h'},
        {"pass",        0,  0,  'p'},
        {"quiet",       0,  0,  'g'},
        {"force",       0,  0,  'f'},
        {"verbose",     0,  0,  'v'},
        {"version",     0,  0,  'V'},
        {"askpass",     0,  0,  'a'},
        {"ondemand",    0,  0,  'o'},
        {0,             0,  0,   0}
    };

int main(int argc, char *argv[])

{
    int cc, digit_optind = 0, loop, loop2;
    struct stat ss; struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    umask(0);

    memset(mountpoint,  0, sizeof(mountpoint));
    memset(mountdata,   0, sizeof(mountdata));
    memset(passprog,    0, sizeof(passprog));
    memset(passx,       0, sizeof(passx));
    memset(decoy,       0, sizeof(decoy));

    // Just for development. DO NOT USE!
    //strcpy(passx, "1234"); //plen = strlen(passx);

    // Parse command line
   	while (1)
        {
        int this_option_optind = optind ? optind : 1;
        int option_index = -1;

    	cc = getopt_long(argc, argv, "a:fhl:p:oqvV",
                         long_options, &option_index);
        if (cc == -1)
            break;

        //printf("cc %d cc %c arg %x\n", cc, cc, optarg);
        //if(option_index >= 0)
        //    {
        //    printf ("long option '%s' idx: %d val %d ",
        //              long_options[option_index].name,
        //              option_index,
        //                long_options[option_index].val);
        //    if (optarg)
        //           printf (" with arg %s", optarg);
        //    printf("\n");
        //    }

        int ret = 0, loop = 0;

        switch (cc)
           {
           case 'a':
                if(verbose)
                    printf("Getting pass from program: '%s'\n", optarg);
                strncpy(passprog, optarg, MAXPASSLEN);
                break;

            case 'f':
                force = 1;
                break;

           case 'l':
               loglevel = atoi(optarg);
                if(verbose)
                    printf("Log Level: %d\n", loglevel);
               break;

           case 'p':
                if (passx[0] != 0)
                    {
                    fprintf(stderr, "%s Error: multiple passes on command line.\n", argv[0]);
                    exit(1);
                    }
                strncpy(passx, optarg, sizeof(passx));
                plen = strlen(passx);
                // Randomize optarg
                for(loop = 0; loop < plen; loop++)
                    {
                    ((char*)optarg)[loop] = rand() % 0x80;
                    }
                if(verbose)
                    printf("Pass provided on command line.\n");
                break;

           case 'q':
               quiet = 1;
               break;

           case 'o':
               ondemand = 1;
               break;

            case 'v':
               verbose = 1;
               break;

           case 'V':
               printf("%s Version: %s\n", argv[0], version);
               exit(0);
               break;

           case 'h': case '?':
                if(verbose)
                    printf("Showing help.\n");
               help(); exit(0);
               break;

           default:
               printf ("?? getopt returned character code 0%o (%c) ??\n", cc, cc);
        }
    }

    // Al least two arguments for md mp
    if (optind >= argc - 1)
        {
        printf("Use: %s -h (or --help) for more information.\n", argv[0]);
		exit(1);
        }

    // Resolve relative paths
    expandpath(argv[optind], mountdata, sizeof(mountdata));
    if(strlen(mountdata) == 0)
        {
        fprintf(stderr,"Must specify mount data directory.");
        help(); exit(2);
        }
    expandpath(argv[optind+1], mountpoint, sizeof(mountpoint));
    if(strlen(mountdata) == 0)
        {
        fprintf(stderr,"Must specify mount data directory.");
        help();  exit(2);
        }
    if (mountdata[strlen(mountdata)-1] != '/')
        strcat(mountdata, "/");

    if (mountpoint[strlen(mountpoint)-1] != '/')
        strcat(mountpoint, "/");

    // Make sure mroot and mdata exists, and are directories

    // 1.) Test for data dir
    if (access(mountdata, R_OK) < 0)
        {
        if(!quiet)
            printf("Cannot access mount data dir: '%s'\n", mountdata);

        if (force)
            {
            if(verbose && !quiet)
                printf("Forcing directory creation.\n");

            if(!quiet)
                printf("Creating mount data dir: '%s'\n", mountdata);

            if (mkdir(mountdata, 0700) < 0)
                {
                fprintf(stderr,"Cannot create mount data dir: '%s'\n", mountdata);
                exit(3);
                }
            }
        else
            {
            exit(2);
            }
        }
    stat(mountdata, &ss);
    if(!S_ISDIR(ss.st_mode))
        {
        fprintf(stderr,"Mount data must be a directory: '%s'\n", mountdata);
        exit(2);
        }

    // 2.) Test for mount point
    if (access(mountpoint, R_OK) < 0)
        {
        if(!quiet)
            printf("Cannot access mount point dir: '%s'\n", mountpoint);

        if (force)
            {
            if(verbose && !quiet)
                printf("Forcing directory creation.\n");

            if(!quiet)
                printf("Creating mount point dir: '%s'\n", mountpoint);

            if (mkdir(mountpoint, 0744) < 0)
                {
                fprintf(stderr,"Cannot create mount point dir: '%s'\n", mountpoint);
                exit(3);
                }
            }
        else
            {
            exit(2);
            }
        }

    stat(mountpoint, &ss);
    if(!S_ISDIR(ss.st_mode))
        {
        fprintf(stderr,"Mount Point must be a directory: '%s'\n", mountpoint);
        exit(2);
        }

    if (verbose && !quiet)
        {
        printf("Mount data dir: '%s'\n", mountdata);
        printf("Mount Point dir: '%s'\n", mountpoint);
        }

    // Make sure they are not nested:
    // These tests are not fool proof, added to TODO
    char *match  = strstr(mountpoint, mountdata);
    if(match)
        {
        fprintf(stderr,"Mount Point must not be nested in Mount Data.\n");
        exit(6);
        }
    char *match2 = strstr(mountdata, mountpoint);
     if(match2)
        {
        fprintf(stderr,"Mount Data must not be nested in Mount Point.\n");
        exit(6);
        }

    // --------------------------------------------------------------------
    // Primitive debug facility. Use tail -f hsenc.log to monitor this file
    // from a separate terminal. We mostly used the log facility.

    openlog("HSENCFS",  LOG_PID,  LOG_DAEMON);

    DIR *dd; struct dirent *dir;
    dd = opendir(mountpoint);
    if (!dd)
        {
        fprintf(stderr,"Cannnot open Mount Point directory\n");
        exit(5);
        }
    int bb = 0;
    for (int aa = 0; aa < 3; aa++)
        {
        if((dir = readdir(dd)) == NULL)
            break;
        bb++;
        }
    closedir(dd);

    if(bb > 2)
        {
        //printf("%s\n", dir->d_name);
        fprintf(stderr,"Mount Point directory not empty, '%s' mounted already.\n", mountpoint);
        exit(5);
        }

    if(loglevel > 0)
        {
        syslog(LOG_DEBUG, "Started with %s\n", mountpoint);
        syslog(LOG_DEBUG, "Using data %s\n", mountdata);
        }

    // Note: if you transform the file with a different block size
    // it will not decrypt.
    //bufsize = ss.st_blksize;
    //printf("Bufsize = %d\n", bufsize);

    bluepoint2_encrypt(decoy, sizeof(decoy), passx, plen);

    if (ondemand)
        {
        if(!passprog[0])
            {
            if(loglevel > 0)
                syslog(LOG_DEBUG, "Started with ondemand and no askpass proram");
            fprintf(stderr,"Must specify askpass program with the ondemand option.\n");
            exit(1);
            }
        // no pass asked for now
        }
    else
        {
        if(passx[0] == 0)
            {
            char tmp[MAXPASSLEN];

            if(passprog[0] != 0)
                {
                if(verbose)
                    printf("Getting pass from program: '%s'\n", passprog);

                char *res = hs_askpass(passprog, tmp, MAXPASSLEN);
                int rlen = strlen(res);
                unsigned long olen = 0;

                if (res && rlen)
                    {
                    unsigned char *res2 = base64_decode(res, rlen, &olen);
                    //strncpy(passx, res, sizeof(passx));
                    strncpy(passx, res2, sizeof(passx));
                    }
                else
                    {
                    if(loglevel > 0)
                        syslog(LOG_DEBUG, "Cannot obtain pass from: '%s'\n", passprog);

                    fprintf(stderr,"Cannot obtain pass from input.\n");
                    exit(4);
                    }
                }
            }
        // Will ask for pass if not filled
        if(pass_ritual(mountpoint, mountdata, passx, &plen))
            {
            fprintf(stderr,"Invalid pass.\n");
            syslog(LOG_AUTH, "Authentication error on mounting by %d '%s' -> '%s'",
                                getuid(), mountdata, mountpoint);
            exit(5);
            }
        }

    if(!quiet)
        {
        if(ondemand)
            printf("Mounting ... with on-demand password.\n");
        else
            printf("Mounting .. %s\n", mountpoint);
        }

    // Write back expanded paths
    argv[optind]    = mountdata;
    argv[optind+1]  = mountpoint;

    // Create INODE directory
    char tmp2[PATH_MAX];
    strncpy(tmp2, mountdata, sizeof(tmp2)); strcat(tmp2, ".inodedata");
    if(stat(tmp2, &ss) < 0)
        {
        if (mkdir(tmp2, 0700) < 0)
            {
            fprintf(stderr,"Cannot create inode data dir: '%s'\n", mountdata);
            exit(3);
            }
        }

    // Skip arguments that are parsed already
    int ret = fuse_main(argc - (optind), &argv[optind], &xmp_oper, NULL);

    // FUSE MAIN terminates ...

    // Inform user, make a log entry
    if(ret)
        {
        if(loglevel > 0)
            syslog(LOG_DEBUG, "Mount returned with '%d'", ret);

        printf("Mounted by uid %d -> %s\n", getuid(), mountpoint);
        printf("Mount returned with '%d'\n", ret);

        syslog(LOG_AUTH, "Cannot mount, attempt by %d '%s' -> '%s'",
                                         getuid(), mountdata, mountpoint);
        }
    else
        {
        if(loglevel > 0)
            syslog(LOG_DEBUG, "Mounted '%s' -> '%s'", mountdata, mountpoint);

        printf("Mounted by uid %d -> %s\n", getuid(), mountpoint);

        syslog(LOG_AUTH, "Mounted by %d '%s' -> '%s'",
                                 getuid(), mountdata, mountpoint);
        }
    return ret;
}




