
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

// ---------------------------------------------------------------------
// Debug the FUSE subsystem without (bypass) the encryption
// Debug the FUSE subsystem with simple (fake) encryption
// Debug the VIRTUAL read/write subsystem, full encryption

//#define BYPASS  1                       // Test case for no interception
#define VIRTUAL 1                     // Newer version of interception

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

extern  char    passx[MAXPASSLEN];
extern  char    mountpoint[PATH_MAX] ;
extern  char    mountsecret[PATH_MAX] ;
extern  char    passprog[PATH_MAX] ;
extern  char    passback[PATH_MAX] ;
extern  char    passprog[PATH_MAX] ;
extern  char    passback[PATH_MAX] ;
extern  char    progname[];

extern  char    *myext;

extern  int     plen;
extern  int     loglevel;
extern  int     pg_debug;
extern  int     verbose;
extern  int     ondemand;

int xmp_read(const char *path, char *buf, size_t wsize, off_t offset,
                         struct fuse_file_info *fi);

int xmp_write(const char *path, const char *buf, size_t wsize,
                        off_t offset, struct fuse_file_info *fi);

int     is_our_file(const char *path, int fname_only);
off_t   get_fsize(int fh);
void    kill_buff(void *bbuff, int xlen);
int     openpass(const char *path);

// EOF
