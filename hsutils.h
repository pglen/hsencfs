// hsutils.h

// Prototypes shared between components

char    *hs_askpass(const char *program, char *buf, int buflen);
void    expandpath(const char *inp, char *outp, int maxlen);
int     pass_ritual(char *mountroot, char *mountdata, char *pass, int *plen);
int     help();





