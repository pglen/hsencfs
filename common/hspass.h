
/* =====[ hspass.h ]=====================================================

   File Name:       hspass.h

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Thu 05.Jun.2025      Peter Glen      Initial version.
      0.00  Sun 08.Jun.2025      Peter Glen      Passarg
      0.00  Sun 15.Jun.2025      Peter Glen      Uninclude hsencfs.

   ======================================================================= */

#define     MAXPASSLEN      256
#define     MARK_SIZE   4096

#define     HS_PROGNAME    "HSENCFS"

extern  char    *myext;
extern  char    defpassx[MAXPASSLEN] ;
extern  char    defpassx2[MAXPASSLEN] ;
extern  char    decoy[MAXPASSLEN] ;
extern  char    decoy2[MAXPASSLEN] ;
extern  char    *progname;

extern  int     gotdefpass;

typedef struct _PassArg
{
    const char    *markfname;
    const char    *passprog;
    const char    *mountstr;
    const char    *prompt;
    const char    *title;
    char    *result;
    int     reslen;
    char    create;
    char    gui;

} PassArg;

#define HSPASS_OK      (0)
#define HSPASS_NOPASS   (-2 -0x100)
#define HSPASS_NOMATCH  (-3 -0x100)
#define HSPASS_MALLOC   (-4 -0x100)
#define HSPASS_NOEXEC   (-5 -0x100)
#define HSPASS_ERRFILE  (-6 -0x100)
#define HSPASS_ERRWRITE (-7 -0x100)

int     create_markfile(const char *name, char *pass, int plen);
int     check_markfile(const char *name, char *pass, int plen);
int     public_encrypt(uchar *data, int data_len, uchar *key, uchar *ebuf);
int     private_decrypt(uchar * enc_data, int data_len, uchar *key, uchar *dbuf);
int     parse_comstr(char *argx[], int limx, const char *program);
void    sigint_local(int sig);
char    *getpassx(char *prompt);
int     hs_askpass(PassArg *parg);
int     pass_ritual(PassArg *parg);
int     getpass_front(PassArg *parg);

//# EOF
