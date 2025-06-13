
/* =====[ xmalloc ]========================================================

   File Name:       xmalloc.c

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Fri 13.Jun.2025      Peter Glen      Initial version.

   ======================================================================= */

// Use a medium amount

// The algorithm dynamically allocates STEP entries at the time.
// When MAX is reached, it recycles the already allocated entries.
// When no recycled entry is available, it ignores the
// supplementary debug information. This assures limits to
// erroneous code, still retaining information that started the error.
// No entries are removed, so no race condition will occur.
// Realloc protected by mutex;

#define  XMALLOC_STEP 100
#define  XMALLOC_MAX  10000

extern int xmalloc_bytes;

//#define  XMALLOC_STEP 2          // test
//#define  XMALLOC_MAX  4

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
