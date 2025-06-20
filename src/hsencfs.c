
/* =====[ hsencfs.sess ]========================================================

   File Name:       hsencfs.c

   Description:     Functions for hsencfs.c

   Revisions:

      REV   DATE                BY              DESCRIPTION
      ----  -----------         ----------      --------------------------
      0.00  Tue 12.Apr.2022     Peter Glen      Virtual remake started
      0.00  Fri 20.Jun.2025     Peter Glen      Close to completion

   ======================================================================= */

/*! \mainpage
 *
 * HSENCFS (High Security EnCrypting File System)
 *
 * High security encryption file system. We make use of the API offered by
 * the fuse subsystem to intercept file operations.
 *
 * The interception is done between mountsecret and mountpoint. Copying data
 * to mountpoint ends up encrypted in mountsecret. Copying data from mountpoint
 * is sourced from mountsecret and decrypted. See "hsencrw.c".
 *
 * Use a dotted file for mountsecret (like .data or .secretdata)
 *
 * One additional useful feature is auditing. Reports file access by user ID.
 * The report is sent to syslog. (use the -l option to turn on log)
 *
 * To make it, type:
 *
 *     make
 *     .. or gcc -lfuse -lulockmgr [localobjects ...] hsencfs.c -o hsencfs
 *
 *  To use it:
 *
 *       hsenc [-f] ~/secrets  [~/.secrets]
 *
 *  Command above will expose the ~/secrets directory. It is sourced from the
 *  backing directory ~/.secrets
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>

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
#include <libgen.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <pwd.h>
#include <signal.h>
#include <getopt.h>

#include "hsencdef.h"
#include "hsencfs.h"
#include "hsutils.h"
#include "base64.h"
#include "xmalloc.h"
#include "hspass.h"
#include "hsencsb.h"
#include "bluepoint2.h"
#include "hsencop.h"
#include "hs_crypt.h"

// -----------------------------------------------------------------------
// Shared flags

int     verbose = 0;
int     nobg = 0;

// Main directories for data / encryption

char  mountpoint[PATH_MAX] = {0, };
char  mountsecret[PATH_MAX] = {0, } ;
char  fullpath[PATH_MAX] = {0, };
char  startdir[PATH_MAX] = {0, };
char  markfile[PATH_MAX] = {0, };

char  passprog[2 * PATH_MAX] = {0, };
char  passback[2 * PATH_MAX] = {0, };

int   ondemand = 1;

// -----------------------------------------------------------------------

// Maintain internal version string
static  char    version[] = "1.5.0";
static  char    build[]   = "Fri 20.Jun.2025";

static  char    tmpsecret[PATH_MAX] ;
static  char    inodedir[PATH_MAX] ;

// -----------------------------------------------------------------------

struct fuse *fuse_op;
struct fuse_session *fuse_sess;

static struct fuse_operations xmp_oper = {
	.init       = xmp_init,
	.getattr	= xmp_getattr,
	//.fgetattr	= xmp_fgetattr,
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
	//.ftruncate	= xmp_ftruncate,
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
	.lseek  	= xmp_lseek,

	//.flag_nullpath_ok = 1,
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

// -----------------------------------------------------------------------
// Simple help

int     helpfunc()

{
    printf("Usage: hsencfs [options] MountPoint [StorageDir] \n");
    printf("MountPoint is a directory for user accessible data. (ex: ~/secret)\n");
    printf("StorageDir (optional) or storing the encrypted data. (ex: ~/.secret)\n");
    printf("Options:  (short / long / ARG / description)\n");
    printf("    -v --verbose        Verbose. Show more details. (add -v for more)\n");
    printf("    -n --nobg           Do not fork to the background.\n");
    printf("    -o --ondemand       Ask pass on command line. Disables 'on-demand' pass. \n");
    printf("    -V --version        Print hsencfs version.\n");
    printf("    -p --pass  PASS     Use pass. Note: clear text pass.\n");
    printf("    -a --askpass PROG   Use this program to ask for pass.\n");
    printf("    -d --debug LEVEL    Debug level. (0-10) Default: 0 (no debug)\n");
    printf("    -l --log LEVEL      Log level. (0-10) Default: 0 (no log)\n");
    printf("Append '--' to the end of command line for FUSE options.\n");
    printf("For example: 'hsencfs ~/secret -- -user-allow-other' for a shared mount.\n");
    printf("Use hsencfs -vh option for more help.\n");
    if (verbose)
        {
        printf("Log levels:  1 - start/stop;   2 - open/create     3 - read/write;\n");
        printf("             4 - all (noisy);  5 - show most  6...10 more details\n");
        printf("Access errors and mount errors are reported stderr and to the log.\n");
        printf("Debug levels: 0 - 10 -- 0 = None  1 = Minimal 10 = Noisy\n");
        printf("The askpass defaults to: 'hsaskpass.py'\n");
        printf("If the askpass starts with '/' it is an absolute path.\n");
        printf("If the askpass starts with '.' it is a relative path\n");
        printf("Otherwise askpass is assumed to be in the executable's home.\n");
        printf("StorageDir defaults to (dot) .MountPontName (ex: ~/.secret)\n");
        printf("Typical invocation: hsencfs  ~/secrets \n");
        printf(" ... the bove command mounts ~/secrets with ~/.secrets as storage dir.\n");
        }
}

//printf("            -u       (--unmount) unmount MountPoint\n");

// -----------------------------------------------------------------------
// Process command line options, set up for mount.

static struct option long_options[] =
    {
        {"loglevel",    1,  0,  'l'},
        {"help",        0,  0,  'h'},
        {"pass",        1,  0,  'p'},
        {"verbose",     0,  0,  'v'},
        {"version",     0,  0,  'V'},
        {"askpass",     0,  0,  'a'},
        {"ondemand",    0,  0,  'o'},
        {"nobg",        0,  0,  'n'},
        {0,             0,  0,   0}
    };

//////////////////////////////////////////////////////////////////////////

int     test_mountpoint(char *ppp, char *mpdir)

{
    int ret = 0; struct stat sss;

    //printf("test_mountpoint() ppp='%s', mpdir=%s\n", ppp, mpdir);
    if(strlen(ppp) == 0)
        {
        fprintf(stderr,"Must specify mount point directory.\n");
        exit(EXIT_ERROR);
        }
    // Resolve relative path
    expandpath(ppp, mpdir, PATH_MAX);
    ret = stat(mpdir, &sss);
    if (ret < 0)
        {
        hsprint(TO_EL, 1, "Mount point '%s' does not exist.", mpdir);
        exit(EXIT_ERROR);
        }
    if(!S_ISDIR(sss.st_mode))
        {
        hsprint(TO_EL, 1, "Mount point must be a directory: '%s'", mpdir);
        exit(EXIT_ERROR);
        }
    return ret;
}

int     test_mountsecret(char *ppp, char *mpdir)

{
    int ret = 0; struct stat sss;

    //printf("test_mountsecret() ppp='%s', mpdir=%s\n", ppp, mpdir);
    if(strlen(ppp) == 0)
        {
         hsprint(TO_EL, 1, "Must specify %s directory.\n", ppp);
        exit(EXIT_ERROR);
        }
    // Resolve relative path
    expandpath(ppp, mpdir, PATH_MAX);
    ret = stat(mpdir, &sss);
    if (ret < 0)
        {
        if(verbose)
            printf("Creating dir: '%s'\n", mpdir);

        //if (mkdir(mpdir, 0755) < 0)
        if (mkdir(mpdir, 0700) < 0)
            {
            fprintf(stderr,"Cannot create mount secret dir: '%s'\n", mpdir);
            exit(EXIT_NOCREATE);
            }
        ret = stat(mpdir, &sss);
        }
    if(!S_ISDIR(sss.st_mode))
        {
         hsprint(TO_EL, 1, "Mount secret must be a directory: '%s'\n", mpdir);
        exit(EXIT_NOCREATE);
        }
    return ret;
}

// ----------------------------------------------------------------------
// Parse command line

void    parse_comline(int argc, char *argv[])

{
    int cc, digit_optind = 0, loop, loop2;
    char *opts = "oqvVfhna:l:p:d:";
    //opterr = 0;

    while (1)
        {
        int this_option_optind = optind ? optind : 1;
        int option_index = -1;

    	cc = getopt_long(argc, argv, opts,
                         long_options, &option_index);

        if (cc == -1)
            {
            //printf("option bailed\n");
            break;
            }
        int ret = 0, loop = 0;
        switch (cc)
           {
           case 'a':
                if (optarg[0] == '/')
                    {
                    // Absolute path
                    snprintf(passprog, sizeof(passprog), "%s", optarg);
                    }
                else
                    {
                    // Relative  path
                    char cwd[PATH_MAX];
                    char *pp = getcwd(cwd, sizeof(cwd));
                    snprintf(passprog, sizeof(passprog), "%s/%s", cwd, optarg);
                    }
                struct stat statbuf;
                int ret = stat(passprog, &statbuf);
                if(ret < 0)
                    {
                    printf("Cannot stat passprog: '%s'\n", passprog);
                    exit(EXIT_NOASKPASS);
                    }
                if(verbose)
                    printf("Setting passprog: '%s'\n", passprog);
                break;
           case 'l':
               loglevel = atoi(optarg);
                if(verbose)
                    printf("Setting log Level: %d\n", loglevel);
               break;
           case 'p':
                if (gotdefpass)
                    {
                    fprintf(stderr, "%s Error: multiple passes on command line.\n", argv[0]);
                    exit(EXIT_ERROR);
                    }
                randmem(decoy, sizeof(decoy));
                fprintf(stderr, "Warning: Cleartext password.\n");
                strcpy(defpassx, optarg);
                //bluepoint2_encrypt(defpassx, sizeof(defpassx), progname, strlen(progname));
                randmem(decoy2, sizeof(decoy));
                randmem(defpassx2, sizeof(defpassx2));
                gotdefpass = TRUE;
                // Randomize optarg
                randmem(optarg, strlen(optarg));
                if(verbose)
                    printf("Pass provided on command line.\n");
                break;
           case 'o':
               ondemand = 0;
               break;
            case 'n':
               nobg = 1;
               break;
            case 'v':
               verbose += 1;
               break;
           case 'V':
               printf("%s Version: %s Fuse Version: %d - Built on: %s \n",
                            argv[0], version, FUSE_USE_VERSION, build);
               exit(EXIT_NOERROR);
               break;
           case 'u':
                //umountx = 1;
                break;
           case 'h':
                if(verbose)
                    printf("Showing help.\n");
               helpfunc(); exit(EXIT_NOERROR);
               break;
           case '?':
                //fprintf(stderr, "%s Error: invalid option on command line.\n",
                //                    argv[0]);
                exit(EXIT_ERROR);
                break;
           default:
               printf ("Invalid option: '%c'\n", cc);
               exit(EXIT_ERROR);
        }
    }
}

void sigenv(int sig)

{
    hsprint(TO_EL, 1, "Received signal: %d", sig);
    fuse_session_unmount(fuse_sess);
    fuse_session_exit(fuse_sess);
    hsprint(TO_EL, 1, "Terminating.");
    _exit(127);
}

void sigterm(int sig)

{
    hsprint(TO_EL, 1, "Received signal: %d", sig);
    fuse_session_unmount(fuse_sess);
    fuse_session_exit(fuse_sess);
    //_exit(127);
}

void sigint(int sig)

{
    hsprint(TO_EL, 1, "Received signal: %d", sig);
    //printf("Received signal: %d\n", sig);
    fuse_session_unmount(fuse_sess);
    fuse_session_exit(fuse_sess);
    //_exit(127);
}

//char tmp[MAXPASSLEN];
// if we are at the terminal, get pass
//if (!isatty(STDOUT_FILENO))
//    {
//    if(passprog[0] != 0)
//        {
//        hsprint(TO_EL, 2, "Getting pass from program: '%s'\n", passprog);
//
//        int ret = hs_askpass(passprog, tmp, sizeof(tmp));
//        if (ret == 0)
//            {
//            //hsprint(TO_EL, 2, "Askpass delivered: '%s'\n", res);
//            // Empty pass ?
//            int rlen = strlen(tmp);
//            if(rlen == 0)
//                {
//                if(verbose)
//                    fprintf(stderr, "Aborted on empty pass from: '%s'\n", passprog);
//                exit(EXIT_NOPASS);
//                }
//            // Decode base64
//            unsigned long olen = 0;
//            unsigned char *res2 = base64_decode(tmp, rlen, &olen);
//            strncpy(defpassx, res2, sizeof(defpassx));
//            plen = strlen(defpassx);
//            free(res2);
//            //hsprint(TO_EL, 2, "defpassx '%s'\n", defpassx);
//            }
//        }
//    }

// Futile attempt
//if (umountx)
//    {
//    if (verbose)
//        printf("Unmounting: '%s'\n", argv[optind]);
//
//    //fuse_unmount( argv[optind]);
//    int ret = umount2(argv[optind], MNT_FORCE);
//    printf("umount %d %s\n", ret, strerror(errno));
//    exit(0);
//    }

// -----------------------------------------------------------------------
// Main entry point

int     main(int argc, char *argv[])

{
    int mainret = 0;

    struct timespec ts;
    struct stat ss; char *msptr = NULL;

    clock_gettime(CLOCK_REALTIME, &ts);
    umask(0);

    char *yy = realpath(argv[0], fullpath);
    split_path(fullpath, startdir, NULL, NULL);

    // Set signal handlers
    signal(SIGSEGV, sigenv);
    signal(SIGTERM, sigterm);
    signal(SIGINT, sigint);

    memset(mountpoint,  0, sizeof(mountpoint));
    memset(mountsecret, 0, sizeof(mountsecret));
    memset(tmpsecret,   0, sizeof(tmpsecret));
    memset(passprog,    0, sizeof(passprog));
    memset(defpassx,    0, sizeof(defpassx));
    memset(decoy,       0, sizeof(decoy));

    // --------------------------------------------------------------------
    // Primitive debug facility. Use tail -f /var/log/hsencfs.log to
    // monitor this file (dependent on your setup it might be the
    // file /var/log/syslog)
    // We mostly use this log facility, but one can monitor from a
    // separate terminal.

    // Init stuff
    //snprintf(passprog, sizeof(passprog), "%s/%s", startdir, "hsaskpass.py");
    snprintf(passprog, sizeof(passprog), "%s", "hsaskpass.py");
    snprintf(passback, sizeof(passback), "%s/%s", startdir, "hsaskpass.sh");
    openlog("HSEncFs",  LOG_PID,  LOG_DAEMON);
    parse_comline(argc, argv);

    // Al least one arguments for md mp
    if (optind >= argc)
        {
        printf("Use: %s -h (or --help) for more information.\n", argv[0]);
		exit(EXIT_NOERROR);
        }
    //printf("optind=%d argc=%d\n", optind, argc);

    hsprint(TO_EL, 2, "Started %s version %s", argv[0], version);

    // Test for mount point
    test_mountpoint(argv[optind], mountpoint);

    // Test for optional mount secret
    if (optind <= argc - 2)
        {
        msptr =  argv[optind+1];
        }
    else
        {
        // Optional data path
        msptr = tmpsecret;
        int cnt = 0, cnt2 = 0; char *pch, *temp;
        // strtok needs different string in successive calls
        char *ddd = xstrdup(mountpoint);
        pch = strtok(ddd, "/");
        while ( (temp = strtok (NULL, "/") ) != NULL)
            {
            //printf("tokenx '%s'\n", temp);
            cnt++;
            }
        xsfree(ddd);
        //printf("cnt %d\n", cnt);
        char *eee = xstrdup(mountpoint);
        pch = strtok(eee, "/");
        strcat(tmpsecret, "/"); strcat(tmpsecret, pch);
        //printf("tokenx '%s'\n", pch);

        while ( (temp = strtok(NULL, "/") ) != NULL)
          {
            cnt2++;
            //printf("token %d  '%s'\n", cnt2, temp);
            if(strcmp(temp, "."))
                {
                strcat(tmpsecret, "/");
                if(cnt2 == cnt)
                    strcat(tmpsecret, ".");
                strcat(tmpsecret, temp);
                }
            }
        xsfree(eee);
        strcat(tmpsecret, "/");
        }

    test_mountsecret(msptr, mountsecret);
    // Make sure mroot and mdata exists, and are directories
    if (verbose)
        {
        printf("Mount  Point dir: '%s'\n", mountpoint);
        printf("Mount Secret dir: '%s'\n", mountsecret);
        }
    // Make sure they are not nested:
    //   Note: these tests are not fool proof, added to TODO
    char *match  = strstr(mountpoint, mountsecret);
    if(match)
        {
        hsprint(TO_EL, 1, "Mount Point must not be nested in Mount Data.");
        exit(EXIT_MOUNTNEST);
        }
    char *match2 = strstr(mountsecret, mountpoint);
     if(match2)
        {
        hsprint(TO_EL, 1, "Mount Data must not be nested in Mount Point.");
        exit(EXIT_MOUNTNEST);
        }
    int mret = ismounted(mountpoint);
    if(mret)
        {
        hsprint(TO_EL, 1, "Directory: '%s' mounted already.", mountpoint);
        exit(EXIT_ALREADY);
        }
    int cntf = countfiles(mountpoint);
    //fprintf(stderr,"Cannnot open MountPoint directory\n");
    if(cntf > 2)
        {
        hsprint(TO_EL, 1, "Cannot mount: '%s'", mountpoint);
        if (verbose)
            hsprint(TO_EL, 1, "Directory not empty or mounted already.");
        exit(EXIT_NONEMPTY);
        }
    bluepoint2_encrypt(defpassx2, sizeof(defpassx2), progname, strlen(progname));
    // Check if valid askpass
    if(ondemand)
        {
        printf("testing: %s\n", passprog);
        int got = 0;
        //if (access(passprog, X_OK) < 0)
        //    {
        //    }
        //else
        //    {
        //
        //    }
        //if (!got)
        //    {
        //    hsprint(TO_EL, 1, "Askpass program '%s' is not an executable.", passprog);
        //    //exit(EXIT_NOASKPASS);
        //    }
        }
    bluepoint2_encrypt(decoy, sizeof(decoy), progname, strlen(progname));

    // Create markfile name
    snprintf(markfile, PATH_MAX, "%s%s", mountsecret, passfname);
    //printf("markfile: '%s'\n", markfile);

    // Just for development. DO NOT USE!
    //strcpy(defpassx, "1234");

    if (!ondemand)
        {
        int pret = 0;
        if (verbose)
            {
            printf("Ondemand pass option deactivated.\n");
            }
        if(gotdefpass)
            {
            printf("getpass comline() '%s'\n", defpassx);
            // Just check
            bluepoint2_encrypt(defpassx, sizeof(defpassx), progname, strlen(progname));
            pret = check_markfile(markfile, defpassx, sizeof(defpassx));
            }
        else
            {
            // Ask for it
            PassArg passarg;

            passarg.result = xmalloc(MAXPASSLEN);
            if(!passarg.result)
                {
                printf("Askpass: no memory.\n");
                pret = HSPASS_MALLOC;
                goto eval_ret;
                }
            memset(passarg.result, '\0', MAXPASSLEN);
            if (access(markfile, R_OK) < 0)
                passarg.create = 1;
            else
                passarg.create = 0;
            passarg.prompt = "\'  Enter pass:  \'",
            passarg.title = mountpoint;
            passarg.gui = 0;
            passarg.passprog = passprog;
            passarg.mountstr = mountpoint;
            passarg.markfname = markfile;
            passarg.reslen = MAXPASSLEN;
            pret = getpass_front(&passarg);
            memcpy(defpassx, passarg.result, MAXPASSLEN);
            free(passarg.result);
            }
         // Do not debug secrets:
        //printf("Pass: '%s'\n", hexdump(defpassx, 16));

       eval_ret:
        if(pret == HSPASS_OK)
            {
            gotdefpass = TRUE;
            }
        else
            {
            gotdefpass = FALSE;

            if(pret == HSPASS_NOPASS)
                hsprint(TO_EL, 0, "Empty pass.");
            else if(pret == HSPASS_NOEXEC)
                hsprint(TO_EL, 0, "Resource (exec askpass prog) problem.");
            else if(pret == HSPASS_ERRFILE)
                hsprint(TO_EL, 0, "Resource (markfile create) problem.");
            else if(pret == HSPASS_ERRWRITE)
                hsprint(TO_EL, 0, "Resource (markfile write) problem.");
            else if (pret == HSPASS_MALLOC)
                hsprint(TO_EL, 0, "Resource (malloc) problem.");
            else
                hsprint(TO_EL, 0, "Invalid password.");
            exit(1);
            }
        }
    // Check access
    if (access(mountpoint, W_OK) < 0)
        {
        hsprint(TO_EL, 9, "No mountpoint write access, fixing.");
        struct stat statbuf; memset(&statbuf, 0, sizeof(statbuf));
        int ret2 = stat(mountpoint, &statbuf);
        //printf("mode2 %d of %s %x\n", ret2, mountpoint, statbuf.st_mode);
        int ret3 = chmod(mountpoint, statbuf.st_mode | S_IWUSR);
        //printf("ret3 %d", ret3);
        }
    // Check access
    if (access(mountsecret, W_OK) < 0)
        {
        hsprint(TO_EL, 9, "No mountdata write access, fixing.");
        struct stat statbuf; memset(&statbuf, 0, sizeof(statbuf));
        int ret2 = stat(mountsecret, &statbuf);
        //printf("mode2 %d of %s %x\n", ret2, mountpoint, statbuf.st_mode);
        int ret3 = chmod(mountsecret, statbuf.st_mode | S_IWUSR);
        //printf("ret3 %d", ret3);
        }
    //xmalloc_verbose = 3;
    hsprint(TO_EL, 2, "MountDir: '%s'", mountpoint);
    hsprint(TO_EL, 2, "DataDir: '%s'", mountsecret);
    int uid = getuid();
    struct passwd *pwd = getpwuid(uid);
    //hsprint(TO_EL, 6, "----------------------------------");
    hsprint(TO_EL, 6, "Started by uid=%d (%s)", uid, pwd->pw_name);
    if(verbose)
        {
        hsprint(TO_EL, 2, "Mounting: '%s'", mountpoint);
        //if(ondemand)
        //    printf("Mounting: '%s' with on-demand password.", mountpoint);
        }
    //hsprint(TO_EL, 1, "Mounting: '%s'", mountpoint);

    // Write back expanded paths
    //char *argv2[6]; int cnt = 0;
    //argv2[cnt++]  = "hsencfs";      argv2[cnt++]  = mountpoint;
    //argv2[cnt++]  = mountsecret;    //argv2[cnt++]  = "user_mmap=1";
    //argv2[cnt++]  = NULL;

    if(verbose)
        printf("Mount parms '%s' '%s'", mountsecret,  mountpoint);

    // Create INODE directory
    //char tmp2[PATH_MAX];
    //strncpy(tmp2, mountsecret, sizeof(tmp2)); strcat(tmp2, ".inodedata");
    //if(stat(tmp2, &ss) < 0)
    //    {
    //    if (mkdir(tmp2, 0700) < 0)
    //        {
    //        fprintf(stderr,"Cannot create inode data dir: '%s'\n", mountsecret);
    //        exit(EXIT_ERROR);
    //        }
    //    }

    // Skip arguments that are parsed already
    // Synthesize new array
    //int ret = fuse_main(2, argv2, &xmp_oper, NULL);

    char *argv3[2] = {NULL};
    argv3[0]  = " ";  argv3[1]  = NULL;
    struct fuse_args fa;
    fa.argc = 1; fa.argv = argv3; fa.allocated = 0;
    fuse_op = fuse_new(&fa, &xmp_oper, sizeof(xmp_oper), NULL);
    fuse_sess = fuse_get_session(fuse_op);
    int ret1 = fuse_mount(fuse_op, mountpoint);

    hsprint(TO_EL, 1, "Mounted '%s'", mountpoint);

    if (!nobg)
        {
        int ret2 = fuse_daemonize(0);
        }
    mainret = fuse_session_loop(fuse_sess);

    // Back from FUSE MAIN
    fuse_opt_free_args(&fa);

    // FUSE MAIN terminates ...
    hsprint(TO_EL, 1, "Unmounting: '%s'", mountpoint);

    // Check access
    if (access(mountpoint, W_OK) >=0 )
        {
        hsprint(TO_EL, 9, "Mountpoint write access, fixing.");
        struct stat statbuf; memset(&statbuf, 0, sizeof(statbuf));
        int ret2 = stat(mountpoint, &statbuf);
        //hsprint(TO_EL, 1, "mode2 %d of %s %x", ret2, mountpoint, statbuf.st_mode);
        int ret3 = chmod(mountpoint, statbuf.st_mode & (~S_IWUSR ));
        //hsprint(TO_EL, 1, "ret3 %d", ret3);
        }
    // Check access
    if (access(mountsecret, W_OK) >=0 )
        {
        hsprint(TO_EL, 9, "Moundata write access, fixing.");
        struct stat statbuf; memset(&statbuf, 0, sizeof(statbuf));
        int ret2 = stat(mountsecret, &statbuf);
        //hsprint(TO_EL, 1, "mode2 %d of %s %x", ret2, mountpoint, statbuf.st_mode);
        int ret3 = chmod(mountsecret, statbuf.st_mode & (~S_IWUSR) );
        //hsprint(TO_EL, 1, "ret3 %d", ret3);
        }

    // Inform user, make a log entry
    if(mainret)
        {
        hsprint(TO_EL, 1, "Mount err: '%s' uid=%d",
                                mountpoint, getuid());
        hsprint(TO_EL, 1, "Mount returned with %d errno=%d",
                                mainret, errno);
        hsprint(TO_EL, 1, "Mounted by uid=%d -> %s", getuid(),
                                        mountpoint);
        hsprint(TO_EL, 1,  "Cannot mount, attempt by user %d '%s' -> '%s'",
                                         getuid(), mountsecret, mountpoint);
        }
    else
        {
        hsprint(TO_EL, 1, "unMnt '%s'", mountpoint);
        hsprint(TO_EL, 1, "unMntSec '%s'", mountsecret);
        }
    return mainret;
}

// EOF