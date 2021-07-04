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

char buff[4096];

int     main(int argc, char *argv[])

{
    //printf("Zigzag read test\n");

    if(argc < 3)
        errexit("Not enough arguments. use: zigzag infile outfile");

    int fp_in = open(argv[1], O_RDWR);
    if(fp_in < 0)
        errexit("no in file");

    int fp_out = open(argv[2], O_RDWR | O_CREAT | O_TRUNC,  S_IRWXU);
    if(fp_out < 0)
        errexit("no out file");

    while(1)
        {
        int ret = read(fp_in, buff, sizeof(buff) / 10);
        if(ret < 0)
            {
            errexit("Cannot read");
            }
        int ret2 = write(fp_out, buff, ret);
        if(ret2 < 0)
            {
            errexit("Cannot write");
            }
        if(ret < sizeof(buff) / 10)
            {
            break;
            }
        int rrr = lseek(fp_in, -110, SEEK_CUR);
        printf("%d ", rrr);

        lseek(fp_out, -110, SEEK_CUR);
        }
    close(fp_in);
    close(fp_out);

}




