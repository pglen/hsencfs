
/* =====[ project ]========================================================

   File Name:       dualwrite.c

   Description:     Seek and write (the last, most enduring test)

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

int     main(int argc, char *argv[])

{
    //printf("Zigzag read test\n");

    if(argc < 3)
        errexit("Not enough arguments. Use: dualwrite infile outfile\n"
                "Write whole, write second half again\n");

    int fp_in = open(argv[1], O_RDWR);
    if(fp_in < 0)
        errexit("no in file"); //, argv[1]);

    int fp_out = open(argv[2], O_RDWR | O_CREAT | O_TRUNC,  S_IRWXU);
    if(fp_out < 0)
        errexit("no out file"); //, argv[2]);

    int fsize = lseek(fp_in, 0, SEEK_END);
    lseek(fp_in, 0, SEEK_SET);
    //printf("Size of file = %d\n", fsize);
    char *pbuff = malloc(fsize);
    if(!pbuff)
        errexit("Cannot allocate buffer.\n");

    int ret = read(fp_in, pbuff, fsize);
    if(ret < 0)
        {
        errexit("Cannot read");
        }
    int ret2 = write(fp_out, pbuff, ret);
    if(ret2 < 0)
        {
        errexit("Cannot write");
        }

    lseek(fp_in, fsize/2, SEEK_SET);
    lseek(fp_out, fsize/2, SEEK_SET);

    ret = read(fp_in, pbuff, fsize);
    if(ret < 0)
        {
        errexit("Cannot read");
        }
    ret2 = write(fp_out, pbuff, ret);
    if(ret2 < 0)
        {
        errexit("Cannot write");
        }
    close(fp_in);  close(fp_out);
}

// EOF
