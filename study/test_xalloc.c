// ------------------------------------------------------------------
// test xmalloc

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "../common/xmalloc.h"
#include "../common/hsutils.h"

// test_strdup()
//{
    //char *strx = "";
    //char *ss = strdup(strx);
    //printf("%p='%s'\n", ss, strx);
    //free(ss);
    //char *ss2 = xstrdup(strx);
    //printf("%p='%s'\n", ss2, strx);
    //xsfree(ss2);
    //exit(0);
//}

int main(int argc, char *argv[])

{
    srand(time(NULL));
    loglevel = 9;

    xmalloc_verbose = 4;
    xmalloc_randfail = 0;

    //void *ppp = malloc(4);
    void *memarr[4];
    int sss = sizeof(memarr)/sizeof(void*);
    for (int aa = 0; aa < sss ; aa++)
        {
        int  memsize = rand() % 100;
        memarr[aa] = xmalloc(memsize);
        if (memarr[aa])
            memset(memarr[aa], 'a', memsize);
        //else
        //    printf("randfail %d\n", aa);

        printf("malloc: %d\n", xmalloc_bytes);
        }
    for (int aa = 0; aa < sss; aa++)
        {
        xsfree(memarr[aa]);
        printf("malloc: %d\n", xmalloc_bytes);
        }
    for (int aa = 0; aa < sss ; aa++)
        {
        int  memsize = rand() % 100;
        memarr[aa] = xmalloc(memsize);
        if (memarr[aa])
            memset(memarr[aa], 'a', memsize);
        printf("malloc: %d\n", xmalloc_bytes);
        }
    for (int aa = 0; aa < sss/2; aa++)
        {
        xsfree(memarr[aa]);
        printf("malloc: %d\n", xmalloc_bytes);
        }
    printf("final malloc: %d\n", xmalloc_bytes);

    //printf("%s\n", hexdump(memarr[0], memsize));
    //xfree(ppp);

    xmdump(0);

    exit(0);
}

// EOF
