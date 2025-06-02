
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

#define  TO_OUT (1 << 0)
#define  TO_ERR (1 << 1)
#define  TO_LOG (1 << 2)

#define  TO_ALL (TO_OUT | TO_ERR | TO_LOG)
#define  TO_EL  (TO_ERR | TO_LOG)
#define  TO_OL  (TO_OUT | TO_LOG)

// Prototypes shared between components

int     ismounted(char *orig);
int     countfiles(char *mpoint);
void    hsprint(int outs, int lev, char *fmt, ...);
void    hslog(int lev, char *fmt, ...);

int     check_markfile(char *name, char *pass, int *plen);
int     create_markfile(char *name, char *pass, int *plen);

char    *hs_askpass(const char *program, char *buf, int buflen);
void    expandpath(const char *inp, char *outp, int maxlen);
int     pass_ritual(char *mountroot, char *mountdata, char *pass, int *plen, char *passprog);

// EOF
