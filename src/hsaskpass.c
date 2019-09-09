/*
 *   Password test routine. 
 */  

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char tmp[256];
int     xlen = 0;

int main(int argc, char *argv[])
{
    char *xpass = getpass("Enter pass for HSENCFS: ");  
    //printf("password: '%s'\n", xpass);
    printf("%s\n", xpass);
    xlen = strlen(xpass);
    memset(xpass, 0, xlen);
    exit(0);
}


