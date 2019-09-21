///////////////////////////////////////////////////////////////////////////
// Bluepoint2 test decrypter. Outputs to stdout.
//

// It blindly decrypts, so make sure if you expect the HSENCFS
// subsystem to accept the file, use the same pass.
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
#include <sys/stat.h>

#include "bluepoint2.h"

/// We use this string to obfuscate the password. Do not change.

char    progname[] = "HSENCFS";

#include "bluepoint2.h"

static char buff[4096];
static char pass[256];
static int plen = 0;

static char tmp[256];

// -----------------------------------------------------------------------

int bpgetpass(const char *fname)

{
    char    *xpass = NULL; int     xlen;

    snprintf(tmp, sizeof(tmp),  "\n"
            "Enter pass for file: '%s'\n"
            "Entering wrong pass will decrypt it incorrectly.\n"
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
        fprintf(stderr, "Usage: bdec2 infile outfile\n");
        exit(1);
        }

    if(access(argv[1], F_OK) < 0)
        {
        fprintf(stderr, "File '%s' must exist and readable.\n", argv[1]);
        exit(1);
        }

    if(access(argv[2], F_OK) >= 0)
        {
        fprintf(stderr, "Output file '%s' must not exist.\n", argv[2]);
        exit(1);
        }

    bpgetpass(argv[1]);

    FILE *fp = fopen(argv[1], "rb");
    if (!fp)
        {
        fprintf(stderr, "File %s must exist.\n", argv[1]);
        exit(1);
        }

    struct stat stbuf;	memset(&stbuf, 0, sizeof(stbuf));
    int res = fstat(fileno(fp), &stbuf);
    if(res < 0)
        {
        fprintf(stderr, "Cannot stat '%s'.\n", argv[1]);
        exit(1);
        }

    off_t fsize = stbuf.st_size;

    FILE *fp2 = fopen(argv[2], "wb");
    if (!fp2)
        {
        fprintf(stderr, "File '%s' must be writable.\n", argv[1]);
        exit(1);
        }

    //ftruncate(fileno(fp2), sizeof(buff));

    while(1)
        {
        memset(buff, 0, sizeof(buff));
        int loop, len, len2;

        len = fread(buff, 1, sizeof(buff), fp);

        if(len <= 0)
            break;

        //hs_decrypt(buff, len, pass, plen);
        hs_decrypt(buff, sizeof(buff), pass, plen);

        len2 = fwrite(buff, 1, sizeof(buff), fp2);

        if(len < sizeof(buff))
            break;
        }

    //ftruncate(fileno(fp2), fsize);
    fclose(fp); fclose(fp2);

    exit(0);
}















