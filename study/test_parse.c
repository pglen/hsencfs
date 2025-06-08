#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <dirent.h>
#include <fuse.h>

int main(int argc, char *argv[])

{
    char *program = "11\\ a 22\"22 33\" '44 55' \"66 'aa' 77\"  ' 88 \"bb\" 99 ' ";

    char *argx[12]; argx[0] = NULL;
    int idx = parse_comstr(argx, 12, program);
    printf("idx: %d\n", idx);
    {   int xx = 0; while(1) {
            hslog(0, "argx ptr: '%s'\n", argx[xx]);
            printf("argx %d ptr: '%s'\n", xx, argx[xx]);
            if(!argx[xx++]) break;
            }
    }

    char *ppp = hexdump(program, strlen(program));
    printf("%s\n", ppp);
    free(ppp);

    exit(0);
}
