
/* =====[ hsencfs ]========================================================

   File Name:       hsencfs.h

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Mon 26.Jul.2021      Peter Glen      Initial version.

   ======================================================================= */

#define FALSE (0==1)
#define TRUE  (0==0)

// This is to debug the FUSE subsystem without the encryption
//#define BYPASS 1                      // Test case for no interception

// This is to debug the VIRTUAL read/write subsystem
#define VIRTUAL 1                       // Newer version of interception

extern  int     plen;
extern  char    passx[MAXPASSLEN];
extern  int     loglevel;
extern  char    *myext;

extern  char  mountpoint[PATH_MAX] ;
extern  char  mountsecret[PATH_MAX] ;
extern  char  passprog[PATH_MAX] ;

int xmp_read(const char *path, char *buf, size_t wsize, off_t offset, // )
                         struct fuse_file_info *fi);

int xmp_write(const char *path, const char *buf, size_t wsize, // )
                        off_t offset, struct fuse_file_info *fi);

void    hslog(int lev, char *fmt, ...);
void    *hsalloc(int total);
int     is_our_file(const char *path, int fname_only);
off_t    get_fsize(int fh);
void    kill_buff(void *bbuff, int xlen);
int     openpass(const char *path);

sideblock_t *alloc_sideblock();
char    *get_sidename(const char *path);
int    read_sideblock(const char *path, sideblock_t *psb);
int     write_sideblock(const char *path, sideblock_t *psb);
int    create_sideblock(const char *path);
void    kill_sideblock(sideblock_t *psb);

// EOF
