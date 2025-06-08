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

static char tmp[256];
int     xlen = 0;

//int     loglevel = 0;
char    progname[] = "HSENCFS";
int     create = 0;
int     gui = 0;
int     verbose = 0;
char    *markfile = "markfile";
char    *defpass = "";

int main(int argc, char *argv[])

{
    //bluepoint2_set_verbose(2);
    char *opts = "vgachm:p:l:";

    openlog("HSEncFs",  LOG_PID,  LOG_DAEMON);
    srand(time(NULL));

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
                printf("Invalid option: -%c \n", optopt);
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
    char *prompt = "Enter pass for HSENCFS: ";
    if(create)
        {
        prompt = "Enter NEW pass for HSENCFS: ";
        }
    int xlen = strlen(defpass);
    char *xpass;
    if(xlen)
        {
        xpass = strdup(defpass);
        }
    else
        {
        PassArg passarg;
        passarg.prompt = "\'  Enter pass:  \'",
        passarg.title = "\' Title Here: \'";
        passarg.gui = gui;
        passarg.create = create;
        passarg.passprog = "../askpass/hsaskpass.py";
        passarg.mountstr = "Mountstr";
        xpass = getpass_front(&passarg);
        }

    //printf("xpass '%s'\n", xpass);

    if(create)
        {
        create_markfile(markfile, xpass, strlen(xpass));
        printf("Created new markfile '%s'.\n", markfile);
        }
    int ret = check_markfile(markfile, xpass, (int)strlen(xpass));
    printf("Check returned: %d.\n", ret);

    exit(0);
}

//# EOF
