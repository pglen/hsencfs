
/* =====[ project ]========================================================

   File Name:       zigzag.c

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Mon 02.Aug.2021      Peter Glen      Initial version.

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

#define ZIGSIZE 4096

char buff[ZIGSIZE];

int     main(int argc, char *argv[])

{
    if(argc < 3)
        errexit("Not enough arguments. use: zigzag infile outfile");

    //printf("Zigzag read test %s\n", argv[1]);

    int fp_in = open(argv[1], O_RDWR);
    if(fp_in < 0)
        errexit("no in file");

    int fp_out = open(argv[2], O_RDWR | O_CREAT | O_TRUNC,  S_IRWXU);
    if(fp_out < 0)
        errexit("no out file");

    //int fsize = lseek(fp_in, 0, SEEK_END);
    //lseek(fp_in, 0, SEEK_SET);
    //printf("%s: fsize=%d -- ", argv[1], fsize);

    while(1)
        {
        int ret = read(fp_in, buff, sizeof(buff));
        if(ret < 0)
            {
            errexit("Cannot read");
            }
        int ret2 = write(fp_out, buff, ret);
        if(ret2 < 0)
            {
            errexit("Cannot write");
            }
        //printf("ret=%d ", ret);
        if(ret < sizeof(buff))
            {
            break;
            }
        int zig = -ZIGSIZE/2;
        int rrr = lseek(fp_in, zig, SEEK_CUR);
        //printf("seek=%d ", rrr);
        int sss = lseek(fp_out, zig, SEEK_CUR);
        //printf("%d \n", sss);
        }
    //printf("\n");

    close(fp_in);
    close(fp_out);
}

// EOF


