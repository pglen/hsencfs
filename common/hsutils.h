// hsutils.h

#define MARK_SIZE 4096

// Prototypes shared between components

int     check_markfile(char *name, char *pass, int *plen);
int     create_markfile(char *name, char *pass, int *plen);

char    *hs_askpass(const char *program, char *buf, int buflen);
void    expandpath(const char *inp, char *outp, int maxlen);
int     pass_ritual(char *mountroot, char *mountdata, char *pass, int *plen);






