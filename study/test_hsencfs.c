
//int loglevel = 0;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>

#define FUSE_USE_VERSION 34
#include <fuse3/fuse.h>

#include "hsencfs.h"
#include "hsutils.h"
#include "xmalloc.h"

int main(int argc, char *argv[])

{
    //printf("hello\n");
    hsprint(TO_ERR|TO_LOG, 1, "Getting pass from program: '%s'\n", "hello2");
}
