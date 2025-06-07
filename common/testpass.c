/*
 *   Password test routine.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include "../src/base64.h"
#include "hsutils.h"
#include "hspass.h"

static char tmp[256];
int     xlen = 0;

int     loglevel = 0;
char    progname[] = "HSENCFS";
int     create = 0;
int     gui = 0;
char    *markfile = "markfile";
char    *defpass = "";

char buff[4096];

char    *getpass_local(char *prompt, int *plen)
{
    int xlen = strlen(defpass);
    if(xlen)
        {
        *plen = xlen;
        return defpass;
        }
    if(gui)
        {
        char *passprog = "../askpass/hsaskpass.py Hello 0";
        int ret = hs_askpass(passprog, buff, sizeof(buff));
        if(ret)
            {
            printf("Error on  pass %d\n", ret);
            exit(1);
            }
        printf("hs_askpass() returned pass: '%s'\n", buff);
        int lenx = strlen(buff);
        if(!lenx)
            {
            printf("No gui pass, aborted.\n");
            exit(1);
            }

        *plen = strlen(buff);
        return buff;
        }
    //"Enter new pass for HSENCFS: ");
    char *xpass = getpassx(prompt);
    *plen = strlen(xpass);
    //printf("password: '%s'\n", xpass);
    if(! *plen)
        {
        printf("No pass, aborted.\n");
        exit(1);
        }
    return xpass;
}

static void hexdump(char *ptr, int len)
{
    int llen = 24;
    for (int aa = 0; aa < len; aa++)
        {
        uchar chh = ptr[aa] & 0xff;
        if(chh > 127 || chh < 32)
            printf("%.2x ", chh);
        else
            printf(" %c ", chh);

        if (aa % llen == llen-1)
            printf("\n");
        }
}

int main(int argc, char *argv[])

{
    //bluepoint2_set_verbose(2);
    char *opts = "gachm:p:";

    openlog("HSEncFs",  LOG_PID,  LOG_DAEMON);

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

            case 'c':
                //printf("option c\n");
                create = 1;
                break;

            case 'm':
                //printf("option m %s\n", optarg);
                markfile = strdup(optarg);
                break;

            case 'p':
                //printf("option m %s\n", optarg);
                defpass = strdup(optarg);
                break;
            }
        }
    if(create)
        {
        int xlen = 0;
        char *xpass = getpass_local("Enter new pass for HSENCFS: ", &xlen);
        create_markfile(markfile, xpass, &xlen);
        printf("Created new markfile with: %s\n", xpass);
        exit(0);
        }
    else
        {
        if(access(markfile, R_OK) < 0)
            {
            printf("Cannot access mark file: '%s'\n", markfile);
            exit(1);
            }
        int xlen = 0;
        char *xpass = getpass_local("Enter pass for HSENCFS: ", &xlen);
        int ret = check_markfile(markfile, xpass, &xlen);
        printf("Check returned: %d.\n", ret);
        }
    //memset(xpass, 0, xlen);
    exit(0);
}

//# EOF
