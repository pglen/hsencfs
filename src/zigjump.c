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
        errexit("Not enough arguments. Use: zigjump infile outfile");

    int fp_in = open(argv[1], O_RDWR);
    if(fp_in < 0)
        errexit("no in file"); //, argv[1]);

    int fp_out = open(argv[2], O_RDWR | O_CREAT | O_TRUNC,  S_IRWXU);
    if(fp_out < 0)
        errexit("no out file"); //, argv[2]);

#if 0
    lseek(fp_in, sizeof(buff), SEEK_SET);
    int  backoffs = 1000;
    int ret5 = lseek(fp_out, 0, SEEK_SET);
    int ret6 = read(fp_out, buff, sizeof(buff) - backoffs);
    int ret7 = lseek(fp_out, sizeof(buff) - backoffs, SEEK_SET);
    int ret2 = write(fp_out, buff, backoffs);
    printf("ret5=%d ret6=%d ret7=%d ret2=%d\n", ret5, ret6, ret7, ret2);
#endif

    //exit(0);

    int endd = lseek(fp_in, 0, SEEK_END);
    lseek(fp_in, 0, SEEK_SET);
    int hhh = 200;
    //printf("End of file = %d\n", endd);

    while(1)
        {
        int eof = lseek(fp_in, 0, SEEK_CUR);
        //printf("Reading at %d\n", eof);
        //if(eof >= endd)
        //    break;

        int ret = read(fp_in, buff, hhh);
        if(ret < 0)
            {
            errexit("Cannot read");
            }
        int ret2 = write(fp_out, buff, ret);
        if(ret2 < 0)
            {
            errexit("Cannot write");
            }

        // End of file
        if(ret < hhh)
            {
            break;
            }
        lseek(fp_in, -hhh/2, SEEK_CUR);
        lseek(fp_out, -hhh/2, SEEK_CUR);
        }

    close(fp_in);  close(fp_out);
}





