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

char buff[500];

int     main(int argc, char *argv[])

{
    if(argc < 3)
        errexit("Not enough arguments. Use: seekcp infile outfile");

    int fp_in = open(argv[1], O_RDWR);
    if(fp_in < 0)
        errexit("no in file");

    int fp_out = open(argv[2], O_RDWR | O_CREAT | O_TRUNC,  S_IRWXU);
    if(fp_out < 0)
        errexit("no out file");

    int fsize = lseek(fp_in, 0, SEEK_END);
    lseek(fp_in, 0, SEEK_SET);
    //printf("File size %d\n", fsize);

    int ret = lseek(fp_in,  fsize + sizeof(buff), SEEK_SET);
    if(ret < 0)
        errexit("Cannot seek in");
    int ret2 = lseek(fp_out, fsize + sizeof(buff), SEEK_SET);
    if(ret2 < 0)
        errexit("Cannot seek out");

    int last = 0;
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
        if(last)
            break;
        int curr = lseek(fp_in, 0, SEEK_CUR);
        //printf("At pos %d\n", curr);
        curr -= 2  * sizeof(buff);
        if(curr < 0)
            {
            curr = 0; last = 1;
            }
        lseek(fp_in, curr, SEEK_SET);
        lseek(fp_out, curr, SEEK_SET);
        }
    close(fp_in);
    close(fp_out);
}



