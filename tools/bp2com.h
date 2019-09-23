// Included in encrypters

#define BLOCKSIZE   4096
#define MAXPASSLEN  256

/// We use this string to obfuscate the password. Do not change.
extern char    progname[];

int     bpgetpass(const char *fname, char *pass, int plenx);

char    *mk_backup_path(const char *path);
int     mk_block_file(const char *path);




