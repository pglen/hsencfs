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
#include <pthread.h>

#include "hsencdef.h"
#include "xmalloc.h"
#include "hsutils.h"

Malloc_Store malloc_store = {0, 0, NULL };

static  int xmalloc_step = XMALLOC_STEP;
static  int xmalloc_max  = XMALLOC_MAX;
static  pthread_mutex_t lock;
static  int  inited = 0;

int  xmalloc_verbose = 0;
int  xmalloc_randfail = 0;
int  xmalloc_bytes = 0;

void    *xmalloc(size_t xsize)

{
    if(!inited)
        {
        if (pthread_mutex_init(&lock, NULL) != 0) {
            hsprint(TO_ERR | TO_LOG, 3, "mutex init has failed");
        }
    inited = 1;
    }

    if(xmalloc_randfail)
        if ( rand() % xmalloc_randfail == 0)
            {
            if(xmalloc_verbose > 0)
                hsprint(TO_ERR | TO_LOG, 3,
                    " xmalloc: random fail on len=%ld", xsize);
            return NULL;
            }
    void *ptr = malloc(xsize);
    if(ptr)
        {
        // Start recycle

        if (malloc_store.curr >= XMALLOC_MAX)
            {
            int found2 = -1;
            for(int bb = 0; bb < malloc_store.curr; bb++)
                {
                if(malloc_store.store[bb].freed != 0)
                    {
                    found2 = bb; break;
                    }
                }
            if(found2 >= 0)
                {
                hsprint(TO_ERR | TO_LOG, 3,
                        "Empty slot: at %d %p",
                                found2, malloc_store.store[found2].ptr);
                malloc_store.store[found2].ptr = ptr;
                malloc_store.store[found2].size = xsize;
                malloc_store.store[found2].freed = 0;
                }
            else
                {
                if(xmalloc_verbose > 3)
                    hsprint(TO_ERR | TO_LOG, 3,
                        "NO Empty slots at: %p %d", ptr, xsize);
                }
            }
        else
            {
            if(malloc_store.curr >= malloc_store.size)
                {
                 pthread_mutex_lock(&lock);

                // Realloc
                size_t newsize = malloc_store.size + xmalloc_step;
                if(xmalloc_verbose > 3)
                    hsprint(TO_ERR | TO_LOG, 3,
                            " xmalloc: store realloc at %ld", newsize);
                malloc_store.store = realloc(malloc_store.store,
                                            sizeof(Malloc) * newsize);
                malloc_store.size = newsize;
                pthread_mutex_unlock(&lock);
                }
            if(xmalloc_verbose > 0)
                hsprint(TO_ERR | TO_LOG, 3,
                        " xmalloc: allocate %p %ld bytes", ptr, xsize);
            malloc_store.store[malloc_store.curr].ptr = ptr;
            malloc_store.store[malloc_store.curr].size = xsize;
            malloc_store.store[malloc_store.curr].freed = 0;
            malloc_store.curr++;
            xmalloc_bytes += xsize;
            }
        }
    else
        {
        if(xmalloc_verbose > 0)
            hsprint(TO_ERR | TO_LOG, 3,
                " xmalloc: allocate failed for %ld", xsize);
        }
    return ptr;
}

static  void    _xsfree(void *ptr, int safe)
{
    int found = -1;
    // Added sequencially, so search backwards
    for(int aa = malloc_store.curr - 1; aa >= 0; aa--)
        {
        if(malloc_store.store[aa].ptr == ptr)
            {
            found = aa; break;
            }
       }
    if (found < 0)
        {
        if(xmalloc_verbose > 0)
            hsprint(TO_ERR | TO_LOG, 3,
                    " xmalloc: no entry on xfree %p", ptr);
        goto endd;
        }
    //hsprint(TO_ERR | TO_LOG, 3, "xsfree: %ld",
    //                  malloc_store.store[found].size );
    if(malloc_store.store[found].freed != 0)
        {
        if(xmalloc_verbose > 0)
            hsprint(TO_ERR | TO_LOG, 3,
                    " xmalloc: Duplicate free  %p", ptr);
        // Skip real free
        goto endd;
        }
    if(safe)
        {
        for(int bb = 0; bb < malloc_store.store[found].size; bb++)
            {
            ((char *)ptr)[bb] = rand() & 0xff;
            }
        }
    if(xmalloc_verbose > 0)
        hsprint(TO_ERR | TO_LOG, 3, " xmalloc: freeing %p %d bytes",
                            ptr, malloc_store.store[found].size);
    malloc_store.store[found].freed = 1;
    xmalloc_bytes -= malloc_store.store[found].size;

  endd: ;
    if(ptr)
        free(ptr);
}

void    xfree(void *ptr)

{
    _xsfree(ptr, 0);
}

void    xsfree(void *ptr)

{
    _xsfree(ptr, 1);
}

void    xmdump(int level)

{
    for(int aa = 0; aa <  malloc_store.curr; aa++)
        {
        if(level)
            {
            hsprint(TO_ERR | TO_LOG, 3, "ptr: %p size: %ld freed: %d",
                    malloc_store.store[aa].ptr,
                            malloc_store.store[aa].size,
                                malloc_store.store[aa].freed);
            }
        else
            {
            if(!malloc_store.store[aa].freed)
                hsprint(TO_ERR | TO_LOG, 3,
                        "Not freed - ptr: %p size: %ld",
                            malloc_store.store[aa].ptr,
                                malloc_store.store[aa].size);
            }
        }
}

//# EOF
