#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>

// Really dumb parse command line to array

void parse_comstr(char *argx[], int limx, char *program)

{
    //printf("parse: '%s'\n", program);

    // Parse command line
    char aa = 0, bb = 0, cc = 0;
    argx[cc] = NULL;
    char curr[128];
    while(1)
        {
        char chh = program[aa];
        //printf("%c", chh);
        if(cc >= limx-1)
            {
            //printf("Warn: argx limit %d\n", cc);
            argx[cc] = NULL;
            break;
            }
        if (chh == '\0')
            {
            //printf("estr: '%s'\n", curr);
            if (curr[0] != '\0')
                {
                argx[cc] = strdup(curr);
                cc++;
                }
            argx[cc] = NULL;
            break;
            }
        else if (chh == ' ')
            {
            //printf("str: '%s'\n", curr);
            if (curr[0] == '\0')
                {
                aa++;
                continue;
                }
            argx[cc] = strdup(curr);
            cc++; bb = 0;
            curr[bb] = '\0';
            }
        else
            {
            curr[bb] = chh;
            bb++;
            curr[bb] = '\0';
            }
        aa++;
        }
}

int     main(int argc, char *argv[])

{
    char *argx[12] ;

    if(argv[1])
        {
        printf("comline: '%s'", argv[1]);
        parse_comstr(argx, 12, argv[1]);
        }
    printf("\n");

    int xx = 0;
    while(1)
        {
        printf("ptr: '%s'\n", argx[xx]);
        if(!argx[xx])
            break;
        xx++;
        }
    xx = 0;
    while(1)
        {
        free(argx[xx]);
        if(!argx[xx])
            break;
        xx++;
        }
}
// EOF
