
/* =====[ project ]========================================================

   File Name:       farwrite.c

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Sat 03.Jul.2021      Peter Glen      Initial version.

   ======================================================================= */

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

int errexit(char *str)
    {
    printf("%s\n", str);
    exit(1);
    }

// -----------------------------------------------------------------------
// Main entry point

char buff[0x100];

int     main(int argc, char *argv[])

{
    if(argc < 2)
        errexit("Not enough arguments. Use: farwrite outfile");

    int fp_out = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if(fp_out < 0)
        errexit("Cannot create out file");

    //int fsize = lseek(fp_out, 0, SEEK_END);
    //lseek(fp_out, 0, SEEK_SET);

    memset(buff, 'a', sizeof(buff));
    lseek(fp_out, 0x300, SEEK_SET);
    int ret2 = write(fp_out, buff, sizeof(buff));
    if(ret2 < 0)
        {
        errexit("Cannot write");
        }

    #if 0
    memset(buff, 'b', sizeof(buff));
    lseek(fp_out, 0x1400, SEEK_SET);
    int ret3 = write(fp_out, buff, sizeof(buff));
    if(ret3 < 0)
        {
        errexit("Cannot write");
        }
   #endif

    close(fp_out);
}



