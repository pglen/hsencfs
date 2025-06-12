
/* =====[ hsencfs.sess ]========================================================

   File Name:       hsencfs.c

   Description:     Functions for hsencfs.c

   Revisions:

      REV   DATE                BY              DESCRIPTION
      ----  -----------         ----------      --------------------------
      0.00  Tue 12.Apr.2022     Peter Glen      Virtual remake started

   ======================================================================= */

// Old header

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

char    defpassx[MAXPASSLEN];
int     defplen = sizeof(defpassx);

//sizeof(defpassx);

// Main directories for data / encryption

char  mountpoint[PATH_MAX] ;
char  mountsecret[PATH_MAX] ;

char  fullpath[PATH_MAX] ;
char  startdir[PATH_MAX];

char  fff[PATH_MAX];
char  eee[PATH_MAX];

char  passprog[2 * PATH_MAX] ;
char  passback[2 * PATH_MAX] ;

char *myext = ".datx";

/// We use this as a string to obfuscate the password. Do not change.
char    progname[] =  HS_PROGNAME;

int   pg_debug = 0;
int   ondemand = 1;

// -----------------------------------------------------------------------

// Maintain internal version string
static  char    version[] = "1.5.0";
static  char    build[]   = "Thu 12.Jun.2025";

// The decoy employed occasionally to stop spyers
// from figuring out where it is stored

static  char    decoy[MAXPASSLEN];
static  int     plen2 = sizeof(decoy);

static  char  tmpsecret[PATH_MAX] ;
static  char  inodedir[PATH_MAX] ;

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
    //printf("\n");
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
        //printf("\n");
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
        hsprint(TO_ERR|TO_LOG, 1, "Mount point '%s' does not exist.", mpdir);
        exit(EXIT_ERROR);
        }
    if(!S_ISDIR(sss.st_mode))
        {
        hsprint(TO_ERR|TO_LOG, 1, "Mount point must be a directory: '%s'", mpdir);
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
         hsprint(TO_ERR|TO_LOG, 1, "Must specify %s directory.\n", ppp);
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
         hsprint(TO_ERR|TO_LOG, 1, "Mount secret must be a directory: '%s'\n", mpdir);
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
        if(pg_debug > 9)
            {
            printf("parse: cc=%c (%d) ", cc, cc);
            if (optarg)
                printf (" with arg '%s'", optarg);
            if(option_index >= 0)
                {
                printf ("\n   -- long option '%s' idx: %d val '%c' ",
                          long_options[option_index].name,
                                option_index, long_options[option_index].val);
                }
            printf("\n");
            }
        int ret = 0, loop = 0;
        switch (cc)
           {
           case 'a':
                if (optarg[0] == '/')
                    {
                    snprintf(passprog, sizeof(passprog), "%s", optarg);
                    }
                else if (optarg[0] == '.')
                    {
                    char cwd[PATH_MAX];
                    char *pp = getcwd(cwd, sizeof(cwd));
                    snprintf(passprog, sizeof(passprog), "%s/%s", cwd, optarg);
                    }
                else
                    {
                    snprintf(passprog, sizeof(passprog), "%s/%s", startdir, optarg);
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

           case 'd':
                pg_debug = atoi(optarg);
                if(verbose)
                    printf("Setting debug level: '%d'\n", pg_debug);
                break;

           case 'l':
               loglevel = atoi(optarg);
                if(verbose)
                    printf("Setting log Level: %d\n", loglevel);
               break;

           case 'p':
                if (defpassx[0] != 0)
                    {
                    fprintf(stderr, "%s Error: multiple passes on command line.\n", argv[0]);
                    exit(EXIT_ERROR);
                    }
                //strcpy(defpassx, optarg, sizeof(defpassx));
                strcpy(defpassx, optarg);
                //defplen = strlen(defpassx);
                // Randomize optarg
                for(loop = 0; loop < strlen(optarg); loop++)
                    {
                    ((char*)optarg)[loop] = rand() % 0x80;
                    }
                if(verbose)
                    printf("Pass provided on command line.\n");

                //if(pg_debug > 5)
                //    printf("Pass '%s' provided on command line.\n", defpassx);

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

// It is a shame that no cross platform split exists

void split_path(const char *path, char *dir, char *fname, char *ext)

{
    int lenx = strlen(path);
    char const *base_name = strrchr(path, '/');
    char const *dot = strrchr(path, '.');

    if(base_name)
        {
        int offs = base_name - path;
        strncpy(dir, path, offs);
        dir[offs] = '\0';
        if (dot != NULL)
            {
            int offs = dot - base_name - 1;
            strncpy(fname, base_name + 1, offs);
            fname[offs] = '\0';
            strcpy(ext, dot + 1);
            ext[lenx - offs] = '\0';
            }
        else
            {
            strcpy(fname, base_name+1);
            strcpy(ext, "");
            }
        }
    else
        {
        strcpy(dir, ".");
        base_name = path;
        if (dot != NULL)
            {
            int offs = dot - base_name;
            strncpy(fname, base_name, offs);
            fname[offs] = '\0';
            strcpy(ext, dot + 1);
            ext[lenx - offs] = '\0';
            }
        else
            {
            strcpy(fname, base_name);
            strcpy(ext, "");
            }
        }
}

void sigterm(int sig)

{
    hsprint(TO_ERR|TO_LOG, 1, "Received signal: %d", sig);
    fuse_session_unmount(fuse_sess);
    fuse_session_exit(fuse_sess);
    //_exit(127);
}

void sigint(int sig)

{
    hsprint(TO_ERR|TO_LOG, 1, "Received signal: %d", sig);
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
//        hsprint(TO_ERR|TO_LOG, 2, "Getting pass from program: '%s'\n", passprog);
//
//        int ret = hs_askpass(passprog, tmp, sizeof(tmp));
//        if (ret == 0)
//            {
//            //hsprint(TO_ERR|TO_LOG, 2, "Askpass delivered: '%s'\n", res);
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
//            //hsprint(TO_ERR|TO_LOG, 2, "defpassx '%s'\n", defpassx);
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
    split_path(fullpath, startdir, fff, eee);

    // Set signal handlers
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
    snprintf(passprog, sizeof(passprog), "%s/%s", startdir, "hsaskpass.py");
    if(pg_debug > 10)
        printf("Passprog: '%s'\n", passprog);
    snprintf(passback, sizeof(passback), "%s/%s", startdir, "hsaskpass.sh");
    if(pg_debug > 10)
        printf("Passback: '%s'\n", passback);

    openlog("HSEncFs",  LOG_PID,  LOG_DAEMON);
    parse_comline(argc, argv);

    if(pg_debug > 9)
        {
        printf("Dir: '%s' file: '%s' ext: '%s'\n", startdir, fff, eee);
        }

    // Al least one arguments for md mp
    if (optind >= argc)
        {
        printf("Use: %s -h (or --help) for more information.\n", argv[0]);
		exit(EXIT_NOERROR);
        }
    //printf("optind=%d argc=%d\n", optind, argc);

    hsprint(TO_ERR|TO_LOG, 1, "Started version %s", version);

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
        char *ddd = strdup(mountpoint);
        pch = strtok(ddd, "/");
        while ( (temp = strtok (NULL, "/") ) != NULL)
            {
            //printf("tokenx '%s'\n", temp);
            cnt++;
            }
        free(ddd);
        //printf("cnt %d\n", cnt);
        char *eee = strdup(mountpoint);
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
        free(eee);
        strcat(tmpsecret, "/");
        }

    if(pg_debug > 9)
        printf("msptr '%s'\n", msptr);
    test_mountsecret(msptr, mountsecret);
    if(pg_debug > 2)
        printf("Mount: '%s' Secret: '%s'\n",  mountpoint, mountsecret);

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
        hsprint(TO_ERR|TO_LOG, 1,
            "Mount Point must not be nested in Mount Data.");
        exit(EXIT_MOUNTNEST);
        }
    char *match2 = strstr(mountsecret, mountpoint);
     if(match2)
        {
        hsprint(TO_ERR|TO_LOG, 1,
            "Mount Data must not be nested in Mount Point.");
        exit(EXIT_MOUNTNEST);
        }
    int mret = ismounted(mountpoint);
    if(mret)
        {
        hsprint(TO_ERR|TO_LOG, 1,
                "Directory: '%s' mounted already.", mountpoint);
        exit(EXIT_ALREADY);
        }
    int cntf = countfiles(mountpoint);
    //fprintf(stderr,"Cannnot open MountPoint directory\n");
    if(cntf > 2)
        {
        hsprint(TO_ERR|TO_LOG, 1, "Cannot mount: '%s'", mountpoint);
        if (verbose)
            hsprint(TO_ERR|TO_LOG, 1,
                    "Directory not empty or mounted already.");
        exit(EXIT_NONEMPTY);
        }

    // Check if valid askpass
    if(ondemand)
        {
        if (access(passprog, X_OK) < 0)
            {
            hsprint(TO_ERR|TO_LOG, -1,
                "Askpass program '%s' is not an executable.", passprog);
            exit(EXIT_NOASKPASS);
            }
        }

    // Note: if you transform the file with a different block size
    // it will not decrypt.
    //bufsize = ss.st_blksize;
    //printf("Bufsize = %d\n", bufsize);

    //bluepoint2_encrypt(decoy, sizeof(decoy), defpassx, defplen);

// Check access
    if (access(mountpoint, W_OK) < 0)
        {
        hsprint(TO_EL, 6, "No mountpoint write access, fixing.");
        struct stat statbuf; memset(&statbuf, 0, sizeof(statbuf));
        int ret2 = stat(mountpoint, &statbuf);
        //printf("mode2 %d of %s %x\n", ret2, mountpoint, statbuf.st_mode);
        int ret3 = chmod(mountpoint, statbuf.st_mode | S_IWUSR);
        //printf("ret3 %d", ret3);
        }
    // Check access
    if (access(mountsecret, W_OK) < 0)
        {
        hsprint(TO_EL, 6, "No mountdata write access, fixing.");
        struct stat statbuf; memset(&statbuf, 0, sizeof(statbuf));
        int ret2 = stat(mountsecret, &statbuf);
        //printf("mode2 %d of %s %x\n", ret2, mountpoint, statbuf.st_mode);
        int ret3 = chmod(mountsecret, statbuf.st_mode | S_IWUSR);
        //printf("ret3 %d", ret3);
        }

    // Just for development. DO NOT USE!
    strcpy(defpassx, "1234");
    //defplen = strlen(defpassx);

    if (!ondemand)
        {
        if (verbose)
            {
            printf("Ondemand pass option deactivated.\n");
            }
        // Will ask for pass if not filled
        //if(defpassx[0] == 0)
        //    {
        //    }

        // Create markfile name
        char *markfile = xmalloc(PATH_MAX);
        snprintf(markfile, PATH_MAX, "%s%s", mountsecret, passfname);
        //printf("markfile: '%s'\n", markfile);

        PassArg passarg;
        if (access(markfile, R_OK) < 0)
            passarg.create = 1;
        else
            passarg.create = 0;

        passarg.prompt = "\'  Enter pass:  \'",
        passarg.title = "\' Title Here: \'";
        passarg.gui = 0;
        passarg.passprog = passprog;
        passarg.mountstr = mountpoint;
        passarg.markfile = markfile;
        char *tmp = malloc(MAXPASSLEN);
        passarg.result = tmp;
        passarg.reslen = MAXPASSLEN;
        int ret = getpass_front(&passarg);
        xsfree(markfile);

        if(ret == HSPASS_OK)
            {
            strcpy(defpassx, passarg.result);
            //defplen = strlen(defpassx);
            printf("Pass OK. '%s' plen=%d\n", defpassx, defplen);
            free(passarg.result);
            }
        else
            {
            if(ret == HSPASS_NOPASS)
                printf("Empty pass.\n");
            else if(ret == HSPASS_NOEXEC)
                printf("Resource (exec askpass prog) problem.\n");
            else if(ret == HSPASS_ERRFILE)
                printf("Resource (markfile create) problem.\n");
            else if(ret == HSPASS_ERRWRITE)
                printf("Resource (markfile write) problem.\n");
            else if (ret == HSPASS_MALLOC)
                printf("Resource (malloc) problem.\n");
            else
                printf("No password match.\n");
            exit(1);
            }

        //int ret2 = pass_ritual(mountpoint, mountsecret, defpassx, &plen, passprog);
        //if(ret2)
        //    {
        //    // Catch abort message
        //    if(ret2 == 3)
        //        hsprint(TO_ERR|TO_LOG, 1,
        //            "Passes do not match, aborted.");
        //    else if(ret2 == 2)
        //       hsprint(TO_ERR|TO_LOG, 1,
        //                "Empty pass entered, aborted.\n");
        //    else
        //        hsprint(TO_ERR|TO_LOG, 1,
        //                "Invalid password entered, aborted.\n");
        //
        //    hsprint(TO_ERR|TO_LOG, 2,
        //            "Authentication error on mounting by %d '%s' -> '%s'",
        //                        getuid(), mountpoint, mountsecret);
        //    exit(EXIT_BADPASS);
        //    }
        }

    hsprint(TO_ERR|TO_LOG, 1, "MountDir: '%s'", mountpoint);
    hsprint(TO_ERR|TO_LOG, 1, "DataDir: '%s'", mountsecret);
    int uid = getuid();
    struct passwd *pwd = getpwuid(uid);
    hsprint(TO_ERR|TO_LOG, 6,
              "Started by uid=%d (%s)", uid, pwd->pw_name);
    if(verbose)
        {
        hsprint(TO_ERR|TO_LOG, 1,
                    "Mounting: '%s'\n", mountpoint);
        //if(ondemand)
        //    printf("Mounting: '%s' with on-demand password.\n", mountpoint);
        }

    //hsprint(TO_ERR|TO_LOG, 1, "Mounting: '%s'\n", mountpoint);

    // Write back expanded paths
    //char *argv2[6]; int cnt = 0;
    //argv2[cnt++]  = "hsencfs";      argv2[cnt++]  = mountpoint;
    //argv2[cnt++]  = mountsecret;    //argv2[cnt++]  = "user_mmap=1";
    //argv2[cnt++]  = NULL;

    if(verbose)
        printf("Mount parms '%s' '%s'\n", mountsecret,  mountpoint);

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

    hsprint(TO_ERR|TO_LOG, 2, "Mounted '%s'", mountpoint);

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
    if (!nobg)
        {
        int ret2 = fuse_daemonize(0);
        }
    mainret = fuse_session_loop(fuse_sess);

    // Back from FUSE MAIN
    fuse_opt_free_args(&fa);

    // FUSE MAIN terminates ...
    hsprint(TO_ERR|TO_LOG, 1, "Unmounting: '%s'", mountpoint);

    // Check access
    if (access(mountpoint, W_OK) >=0 )
        {
        hsprint(TO_ERR|TO_LOG, 1,
                     "Mountpoint write access, fixing.\n");
        struct stat statbuf; memset(&statbuf, 0, sizeof(statbuf));
        int ret2 = stat(mountpoint, &statbuf);
        //hsprint(TO_ERR|TO_LOG, 1, "mode2 %d of %s %x\n", ret2, mountpoint, statbuf.st_mode);
        int ret3 = chmod(mountpoint, statbuf.st_mode & (~S_IWUSR ));
        //hsprint(TO_ERR|TO_LOG, 1, "ret3 %d", ret3);
        }
    // Check access
    if (access(mountsecret, W_OK) >=0 )
        {
        hsprint(TO_ERR|TO_LOG, 1,
                     "Moundata write access, fixing.\n");
        struct stat statbuf; memset(&statbuf, 0, sizeof(statbuf));
        int ret2 = stat(mountsecret, &statbuf);
        //hsprint(TO_ERR|TO_LOG, 1, "mode2 %d of %s %x\n", ret2, mountpoint, statbuf.st_mode);
        int ret3 = chmod(mountsecret, statbuf.st_mode & (~S_IWUSR) );
        //hsprint(TO_ERR|TO_LOG, 1, "ret3 %d", ret3);
        }

    // Inform user, make a log entry
    if(mainret)
        {
        hsprint(TO_ERR|TO_LOG, 1,
                "Mount err: '%s' uid=%d", mountpoint, getuid());
        hsprint(TO_ERR|TO_LOG, 1,
                "Mount returned with %d errno=%d", mainret, errno);
        hsprint(TO_ERR|TO_LOG, 1,
                "Mounted by uid=%d -> %s\n", getuid(), mountpoint);
        hsprint(TO_ERR|TO_LOG, 1,
                "Cannot mount, attempt by user %d '%s' -> '%s'",
                                         getuid(), mountsecret, mountpoint);
        }
    else
        {
        hsprint(TO_ERR|TO_LOG, 1, "unMnt '%s'", mountpoint);
        hsprint(TO_ERR|TO_LOG, 1, "unMntSec '%s'", mountsecret);
        }
    return mainret;
}

// EOF