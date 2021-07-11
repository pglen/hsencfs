
/* =====[ project ]========================================================

   File Name:       hsutils.h

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Wed 07.Jul.2021      Peter Glen      Initial version.

   ======================================================================= */

#define MARK_SIZE   4096

// Included in encrypters

#define BLOCKSIZE   4096

//#define MAXPASSLEN    256
#define MAXPASSLEN      512

#define  HSENCFS_MAGIC  0x34231278

#define     HS_PROGNAME    "HSENCFS"

typedef struct _sideblock

{
    int  magic;                 // Identify
    int  serial;                // Belongs to this block
    int  protocol;              // name of encryption; 0xaa for bluepoint
    int  version;               // Version of encryption 1 for now
    // This way it shows up nicely on screen dumps
    char sep[4];
    //char name[PATH_MAX];
    char buff[ 2 * BLOCKSIZE];
    int  misc2;

} sideblock;

// -----------------------------------------------------------------------
// Init sideblock structure, unified
// serial is -1 so it does not match any block

#define INIT_SIDEBLOCK(sb)                  \
    memset(&(sb), '\0', sizeof((sb)));      \
    (sb).magic =  HSENCFS_MAGIC;            \
    (sb).serial  = -1;                      \
    (sb).protocol = 0xaa;                   \
    (sb).version = 1;                       \
    memcpy((sb).sep, "SB0\n", 4);

// Prototypes shared between components

int     check_markfile(char *name, char *pass, int *plen);
int     create_markfile(char *name, char *pass, int *plen);

char    *hs_askpass(const char *program, char *buf, int buflen);
void    expandpath(const char *inp, char *outp, int maxlen);
int     pass_ritual(char *mountroot, char *mountdata, char *pass, int *plen);

// EOF
