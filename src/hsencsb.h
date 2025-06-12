
/* =====[ hsencsb ]========================================================

   File Name:       hsencsb.h

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Sat 30.Apr.2022      Peter Glen      Initial version.
      0.00  Sat 30.Apr.2022      Peter Glen      moved header items

   ======================================================================= */

#define  HSENCFS_MAGIC  0x34231278

typedef struct _sideblock_t

{
    char    sep[4];            // This way it shows up nicely on screen dumps
    int     magic;             // Identify
    int     serial;            // Belongs to this block
    int     protocol;          // name of encryption; 0xaa for bluepoint
    int     version;           // Version of encryption 1 for now
    size_t  flen;
    int     misc2;
    char    sep2[4];           // This way it shows up nicely on screen dumps

} sideblock_t;

// -----------------------------------------------------------------------
// Init sideblock structure, unified
// serial is -1 so it does not match any block

#define INIT_SIDEBLOCK(sb)                  \
    memset(&(sb), '\0', sizeof((sb)));      \
    (sb).magic =  HSENCFS_MAGIC;            \
    (sb).serial   = -1;                     \
    (sb).protocol = 0xaa;                   \
    (sb).version = 1;                       \
    (sb).flen = 0;                          \
    memcpy((sb).sep,  "SB0\n", 4);          \
    memcpy((sb).sep2, "SB0\n", 4);

sideblock_t *alloc_sideblock();

char    *get_sidename(const char *path);
size_t  get_sidelen(const char *path);
int     read_sideblock(const char *path, sideblock_t *psb);
int     write_sideblock(const char *path, sideblock_t *psb);
int     create_sideblock(const char *path);
void    kill_sideblock(sideblock_t *psb);

// EOF

