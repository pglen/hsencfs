///////////////////////////////////////////////////////////////////////////
// Bluepoint2 test encrypter. Outputs to stdout.
//
// It blindly encrypts, so make sure if you expect the HSENCFS
// subsystem to accept the file, use ythe same pass.
//

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

#include "bluepoint2.h"

char    progname[] = "HSENCFS";

static char buff[4096];
static char pass[256];
static int  plen = 0;
static char tmp[256];

int bpgetpass(const char *fname)

{
    char    *xpass = NULL; int     xlen;

    snprintf(tmp, sizeof(tmp),  "\n"
            "Enter pass for file: '%s'\n"
            "Entering wrong pass will encrypt it incorrectly.\n"
            "Entering empty pass (Return) will Abort.\n"
            "\n"
            "Please enter pass: ", fname);

    xpass = getpass(tmp);  //printf("password: '%s'\n", pass);
    xlen = strlen(xpass);
    if(xlen == 0)
        {
        fprintf(stderr, "Aborted.\n");
        exit(1);
        }

    // Dup the results right away, clear it too
    strncpy(pass, xpass, sizeof(pass));
    memset(xpass, 0, xlen);

    // Always padd it
    if(xlen % 2)
        strncat(pass, "x", sizeof(pass)-1);

    // Encrypt the results right away
    plen = strlen(pass);
    bluepoint2_encrypt(pass, plen, progname, strlen(progname));
}

// -----------------------------------------------------------------------

int main(int argc, char *argv[])

{
    memset(pass, 0, sizeof(pass));

    if(argc < 2)
        {
        fprintf(stderr, "Usage: benc2 infile\n");
        exit(1);
        }

    if(access(argv[1], F_OK) < 0)
        {
        fprintf(stderr, "File '%s' must exist and readable.\n", argv[1]);
        exit(1);
        }

    bpgetpass(argv[1]);

    FILE *fp = fopen(argv[1], "rb");
    if (!fp)
        {
        fprintf(stderr, "File '%s' must be readable.\n", argv[1]);
        exit(1);
        }

    while(1)
        {
        memset(buff, 0, sizeof(buff));
        int loop, len = fread(buff, 1, sizeof(buff), fp);

        if(len <= 0)
            break;

        //hs_encrypt(buff, sizeof(buff), pass, plen);
        hs_encrypt(buff, len, pass, plen);

        for (loop = 0; loop < len; loop++)
            putchar(buff[loop]);

        if(len < sizeof(buff))
            break;
        }

    exit(0);
}
















