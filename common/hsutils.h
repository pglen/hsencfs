
/* =====[ project ]========================================================

   File Name:       hsutils.h

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Wed 07.Jul.2021      Peter Glen      Initial version.
      0.00  Tue 12.Apr.2022      Peter Glen      Reworked for virtual

   ======================================================================= */

typedef unsigned int  uint;
typedef unsigned char uchar;

#define MARK_SIZE   4096

// Included in ALl encrypters

#define BLOCKSIZE   4096
#define MAXPASSLEN      512

#define     HS_PROGNAME    "HSENCFS"

// Prototypes shared between components

int     check_markfile(char *name, char *pass, int *plen);
int     create_markfile(char *name, char *pass, int *plen);

char    *hs_askpass(const char *program, char *buf, int buflen);
void    expandpath(const char *inp, char *outp, int maxlen);
int     pass_ritual(char *mountroot, char *mountdata, char *pass, int *plen);

// EOF
