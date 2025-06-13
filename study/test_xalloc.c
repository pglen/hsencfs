// ------------------------------------------------------------------
// test xmalloc

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "../common/xmalloc.h"
#include "../common/hsutils.h"


int main(int argc, char *argv[])

{
    srand(time(NULL));

    loglevel = 9;

    char *strx = "";
    char *ss = strdup(strx);
    printf("%p='%s'\n", ss, strx);
    free(ss);

    char *ss2 = xstrdup(strx);
    printf("%p='%s'\n", ss2, strx);
    xsfree(ss2);

    exit(0);

    //xmalloc_verbose = 0;
    //xmalloc_randfail = 0;

    //void *ppp = malloc(4);
    void *memarr[8];
    int sss = sizeof(memarr)/sizeof(void*);
    for (int aa = 0; aa < sss ; aa++)
        {
        int  memsize = rand() % 100;
        memarr[aa] = xmalloc(memsize);
        if (memarr[aa])
            memset(memarr[aa], 'a', memsize);
        //else
        //    printf("randfail %d\n", aa);
        }
    for (int aa = 0; aa < sss; aa++)
        {
        //if (memarr[aa])
            {
            xsfree(memarr[aa]);
            //if (aa %2 == 0)
            //    {
            //    xsfree(memarr[aa]);
            //    }
            }
        }
    //printf("%s\n", hexdump(memarr[0], memsize));
    //xfree(ppp);

    xmdump(0);

    exit(0);
}

// EOF
