// ------------------------------------------------------------------
// test xmalloc

int loglevel = 0;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "../common/xmalloc.h"

int main(int argc, char *argv[])

{
    srand(time(NULL));

    //xmalloc_verbose = 1;
    xmalloc_randfail = 3;

    int  memsize = 30;
    void *ppp = malloc(20);
    void *memarr[10];
    int sss = sizeof(memarr)/sizeof(void*);
    for (int aa = 0; aa < sss ; aa++)
        {
        memarr[aa] = xmalloc(memsize);
        if (memarr[aa])
            memset(memarr[aa], 'a', memsize);
        //else
        //    printf("randfail %d\n", aa);
        }
    for (int aa = 0; aa < sss; aa++)
        {
        if (memarr[aa])
            if (aa %2 == 0)
                xsfree(memarr[aa]);
        }
    //printf("%s\n", hexdump(memarr[0], memsize));
    xfree(ppp);
    xmdump(0);
    exit(0);
}

// EOF
