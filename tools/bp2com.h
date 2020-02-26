// Included in encrypters

#define BLOCKSIZE   4096
#define MAXPASSLEN  256

#define  HSENCFS_MAGIC 0x34231278

typedef struct _sideblock

{
    int  magic;
    int  serial;
    int  misc;
    //char name[PATH_MAX];
    char buff[HS_BLOCK];

} sideblock;

/// We use this string to obfuscate the password. Do not change.
extern char    progname[];

int     bpgetpass(const char *fname, char *pass, int *plenx);
char    *mk_backup_path(const char *path);
int     mk_block_file(const char *path);






