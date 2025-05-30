#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

// It is a shame that no cross platform split exists

void split_path(const char *path, char *dir, char *fname, char *ext)

{
    int lenx = strlen(path);
    char const *base_name = strrchr(path, '/');
    char const *dot = strrchr(path, '.');

    if(base_name)
        {
        int offs = base_name - path;
        strncpy(dir, path, offs);
        dir[offs] = '\0';
        if (dot != NULL)
            {
            int offs = dot - base_name - 1;
            strncpy(fname, base_name + 1, offs);
            fname[offs] = '\0';
            strcpy(ext, dot + 1);
            ext[lenx - offs] = '\0';
            }
        else
            {
            strcpy(fname, base_name+1);
            strcpy(ext, "");
            }
        }
    else
        {
        strcpy(dir, ".");
        base_name = path;
        if (dot != NULL)
            {
            int offs = dot - base_name;
            strncpy(fname, base_name, offs);
            fname[offs] = '\0';
            strcpy(ext, dot + 1);
            ext[lenx - offs] = '\0';
            }
        else
            {
            strcpy(fname, base_name);
            strcpy(ext, "");
            }
        }
}

char fullpath[PATH_MAX];
char dd[PATH_MAX];
char ff[PATH_MAX];
char ee[PATH_MAX];

int     main(int argc, char *argv[])

{
    char *yy = realpath(argv[0], fullpath);
    printf("full: '%s'\n", fullpath);
    split_path(fullpath, dd, ff, ee);
    printf("dir: '%s'\n", dd);
    printf("file: '%s.%s'\n", ff, ee);
    printf("ff: '%s'\n", ff);
    printf("ee: '%s'\n", ee);
    printf("\n");

    if (argv[1])
        {
        split_path(argv[1], dd, ff, ee);
        printf("dd: '%s'\n", dd);
        printf("ff: '%s'\n", ff);
        printf("ee: '%s'\n", ee);
        printf("\n");
        }

    if (argv[2])
        {
        split_path(argv[2], dd, ff, ee);
        printf("dd: '%s'\n", dd);
        printf("ff: '%s'\n", ff);
        printf("ee: '%s'\n", ee);
        printf("\n");
        }
}
