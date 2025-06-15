// ------------------------------------------------------------------
// test xmalloc

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>

#include "../common/xmalloc.h"
#include "../common/hsutils.h"

char dir[PATH_MAX], fname[PATH_MAX], ext[PATH_MAX];

int main(int argc, char *argv[])

{
    //printf("prog: '%s'\n", argv[0]);
    if(argc < 2)
        {
        printf("use: test_split fullpath\n");
        exit(0);
        }
    split_path(argv[1], dir, fname, ext);
    printf("full: '%s' dir: '%s' fname: '%s' ext:, '%s'\n", argv[1], dir, fname, ext);
    split_path(argv[1], dir, NULL, NULL);
    printf("full: '%s' dir: '%s'\n", argv[1], dir);

    exit(0);
}

// EOF
