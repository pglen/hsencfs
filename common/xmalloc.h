
typedef struct _Malloc
{
    void    *ptr;
    int     size;
    char    freed;
} Malloc;

typedef struct _Malloc_Store
{
    int     curr ;
    int     size ;
    Malloc *store;
} Malloc_Store;

extern int  xmalloc_verbose;
extern int  xmalloc_randfail;

void    *xmalloc(int size);
void    xfree(void *ptr);
void    xsfree(void *ptr);
void    xmdump(int level);

// EOF
