
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

char    pbuff[101];

// -----------------------------------------------------------------------
// Main entry point

int     main(int argc, char *argv[])

{
    if(argc < 2)
        errexit("Not enough arguments. Use: dualread infile\n"
                "Read 100 until done, print the file to stdout\n");

    int fp_in = open(argv[1], O_RDWR);
    if(fp_in < 0)
        errexit("no in file"); //, argv[1]);

    //int fsize = lseek(fp_in, 0, SEEK_END);
    //lseek(fp_in, 0, SEEK_SET);
    //printf("Size of file = %d\n", fsize);

    //char *pbuff = malloc(100);
    //if(!pbuff)
    //    errexit("Cannot allocate buffer.\n");

    for(;;)
        {
        int ret = read(fp_in, pbuff, 100);
        if(ret < 0)
            {
            errexit("Cannot read");
            }

        if(ret == 0)
            break;

        pbuff[ret] = '\0';
        printf("'%s'", pbuff);
        }

    close(fp_in);
    //free(pbuff);
}

// EOF
