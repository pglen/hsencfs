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
//char buff[1024];

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

    int fsize = lseek(fp_in, 0, SEEK_END);
    lseek(fp_in, 0, SEEK_SET);
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
        int zig = -256;
        int rrr = lseek(fp_in, zig, SEEK_CUR);
        //printf("seek=%d ", rrr);
        int sss = lseek(fp_out, zig, SEEK_CUR);
        //printf("%d \n", sss);
        }
    //printf("\n");

    close(fp_in);
    close(fp_out);
}




