
int loglevel = 0;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common/hsutils.h"

int main(int argc, char *argv[])

{
    srand(time(NULL));
    malloc_verbose = 0;

    int  memsize = 30;
    //void *ppp = malloc(20);
    void *memarr[10];
    int sss = sizeof(memarr)/sizeof(void*);
    for (int aa = 0; aa < sss ; aa++)
        {
        memarr[aa] = xmalloc(memsize);
        memset(memarr[aa], 'a', memsize);
        }
    for (int aa = 0; aa < sss; aa++)
        {
        if (aa %2 == 0)
            xsfree(memarr[aa]);
        }
    printf("%s\n", hexdump(memarr[0], memsize));
    //xfree(ppp);
    xmdump(0);
    exit(0);
}
