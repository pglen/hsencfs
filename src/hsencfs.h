
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

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#define MAXPASSLEN      256

typedef unsigned int  uint;
typedef unsigned char uchar;

#define     HS_PROGNAME    "HSENCFS"
#define     MARK_SIZE   4096

#define EXIT_NOERROR    0
#define EXIT_ERROR      1
#define EXIT_ALREADY    2
#define EXIT_NONEMPTY   3
#define EXIT_NOASKPASS  4
#define EXIT_NOCREATE   5
#define EXIT_MOUNTNEST  6
#define EXIT_NOPASS     7
#define EXIT_BADPASS    8

// ---------------------------------------------------------------------
// Debug the FUSE subsystem without (bypass) the encryption
// Debug the FUSE subsystem with simple (fake) encryption
// Debug the VIRTUAL read/write subsystem, full encryption

//#define BYPASS  1                       // Test case for no interception
#define VIRTUAL 1                         // Newer version of interception

// Warning: this will disable all encryptions;
// This is used for testing ONLY;

// -----------------------------------------------------------------------
// Test cases for simplifying and / or disabling encryption
// Nothing defined yields error
// FULL_ENCRYPT activates the real encryption

//#define NONE_ENCRYPT      1
//#define FAKE_ENCRYPT    1
//#define HALF_ENCRYPT    1
#define FULL_ENCRYPT    1

extern  char    defpassx[MAXPASSLEN];

extern  char    mountpoint[PATH_MAX] ;
extern  char    mountsecret[PATH_MAX] ;
extern  char    passprog[PATH_MAX] ;
extern  char    passback[PATH_MAX] ;
extern  char    passprog[PATH_MAX] ;
extern  char    passback[PATH_MAX] ;
extern  char    progname[];

extern  char    *myext;

extern  int     defplen;
extern  int     pg_debug;
extern  int     verbose;
extern  int     ondemand;

int xmp_read(const char *path, char *buf, size_t wsize, off_t offset,
                         struct fuse_file_info *fi);

int xmp_write(const char *path, const char *buf, size_t wsize,
                        off_t offset, struct fuse_file_info *fi);

int     is_our_file(const char *path, int fname_only);
off_t   get_fsize(int fh);
char    *alloc_path2(const char *path);
void    kill_buff(void *bbuff, int xlen);
int     openpass(const char *path);

// EOF
