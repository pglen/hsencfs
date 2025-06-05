
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

#define     HS_PROGNAME    "HSENCFS"

#define  TO_OUT (1 << 0)
#define  TO_ERR (1 << 1)
#define  TO_LOG (1 << 2)

#define  TO_ALL (TO_OUT | TO_ERR | TO_LOG)
#define  TO_EL  (TO_ERR | TO_LOG)
#define  TO_OL  (TO_OUT | TO_LOG)

extern  char    *passfname;

// Prototypes shared between components

int     ismounted(char *orig);
int     countfiles(char *mpoint);
void    hsprint(int outs, int lev, char *fmt, ...);
void    hslog(int lev, char *fmt, ...);
void    expandpath(const char *inp, char *outp, int maxlen);

// EOF
