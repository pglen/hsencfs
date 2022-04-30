
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
    int  magic;                 // Identify
    int  serial;                 // Belongs to this block
    int  serial2;                // Belongs to this block
    int  serial3;                // Belongs to this block
    int  protocol;              // name of encryption; 0xaa for bluepoint
    int  version;               // Version of encryption 1 for now
    size_t flen;
    // This way it shows up nicely on screen dumps
    char sep[4];
    //char name[PATH_MAX];
    char buff[HS_BLOCK];
    //char buff2[HS_BLOCK];
    //char buff3[HS_BLOCK];
    //char buff[ 2 * HS_BLOCK];
    int  misc2;

} sideblock_t;

// -----------------------------------------------------------------------
// Init sideblock structure, unified
// serial is -1 so it does not match any block

#define INIT_SIDEBLOCK(sb)                  \
    memset(&(sb), '\0', sizeof((sb)));      \
    (sb).magic =  HSENCFS_MAGIC;            \
    (sb).serial   = -1;                     \
    (sb).serial2  = -1;                     \
    (sb).serial3  = -1;                     \
    (sb).protocol = 0xaa;                   \
    (sb).version = 1;                       \
    memcpy((sb).sep, "SB0\n", 4);

// EOF

