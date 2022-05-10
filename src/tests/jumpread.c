
/* =====[ project ]========================================================

   File Name:       onejump.c

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

char buff[10];

int     main(int argc, char *argv[])

{
    if(argc < 2)
        errexit("Not enough arguments. Use: jumpread outfile");

    int fp_out = open(argv[1], O_RDWR | O_CREAT | O_TRUNC,  S_IRWXU);
    if(fp_out < 0)
        errexit("no out file");

    lseek(fp_out, 100, SEEK_SET);
    int ret = read(fp_out, buff, sizeof(buff));

    int fsize = lseek(fp_out, 0, SEEK_END);
    //printf("fsize: %d\n", fsize);

    memset(buff, 'a', sizeof(buff));
    lseek(fp_out, 120, SEEK_SET);
    int ret2 = write(fp_out, buff, sizeof(buff));
    if(ret2 < 0)
        {
        errexit("Cannot write");
        }

    memset(buff, 'b', sizeof(buff));
    lseek(fp_out, 40, SEEK_SET);
    int ret3 = write(fp_out, buff, sizeof(buff));
    if(ret3 < 0)
        {
        errexit("Cannot write");
        }

    memset(buff, 'c', sizeof(buff));
    lseek(fp_out, 200, SEEK_SET);
    int ret4 = write(fp_out, buff, sizeof(buff));
    if(ret4 < 0)
        {
        errexit("Cannot write");
        }
    close(fp_out);
    //printf("Done jr\n");
}



