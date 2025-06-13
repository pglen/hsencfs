
/* =====[ xmalloc ]========================================================

   File Name:       xmalloc.c

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Fri 13.Jun.2025      Peter Glen      Initial version.

   ======================================================================= */

// Use a medium amount

#define XMALLOC_STEP 100

typedef struct _Malloc
{
    void        *ptr;
    size_t      size;
    char        freed;
} Malloc;

typedef struct _Malloc_Store
{
    size_t     curr ;
    size_t     size ;
    Malloc *store;
} Malloc_Store;

extern int  xmalloc_verbose;
extern int  xmalloc_randfail;

void    *xmalloc(size_t size);
void    xfree(void *ptr);
void    xsfree(void *ptr);
void    xmdump(int level);

// EOF
