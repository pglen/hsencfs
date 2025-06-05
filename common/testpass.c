/*
 *   Password test routine.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hsutils.h"
#include "hspass.h"

static char tmp[256];
int     xlen = 0;

int     loglevel = 0;
char    progname[] = "HSENCFS";

int main(int argc, char *argv[])

{
    //bluepoint2_set_verbose(2);

    char *xpass = getpass("Enter pass for HSENCFS: ");
    //printf("password: '%s'\n", xpass);
    xlen = strlen(xpass);
    if(xlen)
        {
        if(argc > 1)
            {
            //printf("%s\n", xpass);
            create_markfile("markfile", xpass, &xlen);
            printf("Created new markfile\n");
            }
        else
            {
            int ret = check_markfile("markfile", xpass, &xlen);
            printf("Check %d\n", ret);
            }
        }
    else
        {
        printf("No pass, aborted.\n");
        }
    memset(xpass, 0, xlen);
    exit(0);
}




