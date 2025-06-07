
/* =====[ hspass.h ]=====================================================

   File Name:       hspass.h

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Thu 05.Jun.2025      Peter Glen      Initial version.

   ======================================================================= */

int     seccomp(const uchar *s1, const uchar *s2, int len);
int     create_markfile(char *name, char *pass, int plen);
int     check_markfile(char *name, char *pass, int plen);
int     public_encrypt(uchar *data, int data_len, uchar *key, uchar *ebuf);
int     private_decrypt(uchar * enc_data, int data_len, uchar *key, uchar *dbuf);
void    parse_comstr(char *argx[], int limx, const char *program);
void    sigint_local(int sig);
char    *getpassx(char *prompt);
int     hs_askpass(const char *program, char *buf, int buflen);
int     pass_ritual(char *mroot, char *mdata, char *pass, int *plen, char *passprog);

//# EOF
