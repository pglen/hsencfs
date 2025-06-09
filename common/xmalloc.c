/*
 *  High security encryption file system. We make use of the API offered by
 *  the fuse subsystem to intercept file operations.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <fuse.h>
#include <ulockmgr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>
#include <syslog.h>
#include <mntent.h>
#include <stdarg.h>

#include "xmalloc.h"

Malloc_Store malloc_store = {0, 0, NULL };

static  int xmalloc_step = 100;

int  xmalloc_verbose = 0;
int  xmalloc_randfail = 0;

void    *xmalloc(int size)

{
    if(xmalloc_randfail)
        if ( rand() % xmalloc_randfail == 0)
            {
            if(xmalloc_verbose > 0)
                printf("xmalloc: random fail on len=%d\n", size);
            return NULL;
            }
    char *ptr = malloc(size);
    if(ptr)
        {
        if(xmalloc_verbose > 0)
            printf("xmalloc: %d %p\n", size, ptr);

        if(malloc_store.curr >= malloc_store.size)
            {
            // Realloc
            int newsize = malloc_store.size + xmalloc_step;
            if(xmalloc_verbose > 1)
                printf("realloc at %d\n", newsize);
            malloc_store.store = realloc(malloc_store.store,
                                        sizeof(Malloc) * newsize);
            malloc_store.size = newsize;
            }
        malloc_store.store[malloc_store.curr].ptr = ptr;
        malloc_store.store[malloc_store.curr].size = size;
        malloc_store.store[malloc_store.curr].freed = 0;

        malloc_store.curr++;
        }
    return ptr;
}

void    xsfree(void *ptr)
{
    // safe free
    int found = -1;
    for(int aa = 0; aa <  malloc_store.curr; aa++)
        {
        if(malloc_store.store[aa].ptr == ptr)
            {
            found = aa;
            }
       }
    if (found < 0)
        {
        if(xmalloc_verbose > 0)
            printf("Error on xfree: %p\n", ptr);
        }
    else
        {
        //printf("xsfree: %d\n", malloc_store.store[found].size );
        for(int bb = 0; bb < malloc_store.store[found].size; bb++)
            {
            ((char *)ptr)[bb] = rand() & 0xff;
            }
        malloc_store.store[found].freed = 1;
        }
    free(ptr);
}

void    xfree(void *ptr)

{
    if(xmalloc_verbose > 1)
        printf("freeing %p ... ", ptr);

    int found = -1;
    for(int aa = 0; aa <  malloc_store.curr; aa++)
        {
        if(malloc_store.store[aa].ptr == ptr)
            {
            if(xmalloc_verbose > 3)
                printf("ptr: %p size: %d freed: %d\n",
                    malloc_store.store[aa].ptr,
                             malloc_store.store[aa].size,
                                malloc_store.store[aa].freed);
            found = aa;
            }
        }
    if (found < 0)
        {
        if(xmalloc_verbose > 0)
            printf("Error on xfree: %p\n", ptr);
        }
    else
        {
        malloc_store.store[found].freed = 1;
        }
    // Free it, even if not in our database
    free(ptr);
}

void    xmdump(int level)

{
    for(int aa = 0; aa <  malloc_store.curr; aa++)
        {
        if(level)
            {
            printf("ptr: %p size: %d freed: %d\n",
                    malloc_store.store[aa].ptr,
                            malloc_store.store[aa].size,
                                malloc_store.store[aa].freed);
            }
        else
            {
            if(!malloc_store.store[aa].freed)
                printf("Not freed - ptr: %p size: %d\n",
                    malloc_store.store[aa].ptr,
                            malloc_store.store[aa].size);
            }
        }
}

//# EOF
