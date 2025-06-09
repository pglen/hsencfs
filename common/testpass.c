/*
 *   Password test routine.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <dirent.h>
#include <fuse.h>

#include "hsencfs.h"
#include "base64.h"
#include "hsutils.h"
#include "hspass.h"
#include "xmalloc.h"

static char tmp[MAXPASSLEN];
int     xlen = 0;

char    progname[] = "HSENCFS";
int     create = 0;
int     gui = 0;
int     verbose = 0;
char    *markfile = "markfile";
char    *defpass = "";
char    *askprog = "../askpass/hsaskpass.py";

int main(int argc, char *argv[])

{
    //bluepoint2_set_verbose(2);
    char *opts = "vgachm:p:l:k:";

    openlog("HSEncFs",  LOG_PID,  LOG_DAEMON);
    srand(time(NULL));

    //xmalloc_randfail = 3;

    while (1)
        {
        opterr = 0;
    	char cc = getopt(argc, argv, opts);
        if (cc == -1)
            {
            //printf("option bailed\n");
            break;
            }
        switch (cc)
            {
            case ':':
                printf("Missing option arg: -%c \n", optopt);
                exit(1);
                break;

            case '?':
                printf("Invalid option or missing argument: -%c \n", optopt);
                exit(1);
                break;

            case 'h':
                printf("options: %s\n", opts);
                exit(0);
                break;

            case 'g':
                //printf("option a\n");
                gui = 1;
                break;

            case 'v':
                //printf("option a\n");
                verbose += 1;
                break;

            case 'c':
                //printf("option c\n");
                create = 1;
                break;

            case 'm':
                //printf("option m %s\n", optarg);
                markfile = strdup(optarg);
                break;

            case 'l':
                loglevel = atoi(optarg);
                printf("loglevel: %d\n", loglevel);
                break;

            case 'p':
                //printf("option m %s\n", optarg);
                defpass = strdup(optarg);
                break;

            case 'k':
                //printf("option g %s\n", optarg);
                askprog = strdup(optarg);
                break;
            }
        }

    hsprint(TO_ERR | TO_OUT | TO_LOG, 3, "Starting testpass '%s'", argv[0]);

    if(!create)
        {
        if(access(markfile, R_OK) < 0)
            {
            printf("Cannot access mark file: '%s'\n", markfile);
            //exit(1);
            create = 1;
            }
        }
    PassArg passarg;
    passarg.prompt = "\'  Enter pass:  \'",
    passarg.title = "\' Title Here: \'";
    passarg.gui = gui;
    passarg.create = create;
    passarg.passprog = askprog;
    passarg.mountstr = "Mountstr";
    passarg.markfile = markfile;
    int ret = getpass_front(&passarg);

    if(ret == HSPASS_OK)
        printf("Pass OK.\n");
    else if(ret == HSPASS_NOPASS)
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

    //printf("getpass_front ret: %d\n", ret);

    exit(0);
}

//# EOF
