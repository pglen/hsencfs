/// We use this string to obfuscate the password. Do not change.

//extern char    *progname[];
#define BLOCKSIZE       4096

int     bpgetpass(const char *fname, char *pass, int *plenx);
char    *mk_backup_path(const char *path);
int     mk_block_file(const char *path);

// EOF
