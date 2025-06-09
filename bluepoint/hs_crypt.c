// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//

#define _GNU_SOURCE

#include <fuse.h>
#include <ulockmgr.h>

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <sys/time.h>

#include "hsencfs.h"
#include "bluepoint2.h"
#include "hs_crypt.h"

#ifdef NONE_ENCRYPT

//#warning "None encryption, (does nothing) for testing only"

void hs_encrypt_none(void *mem, int size2, void *pass, int plen)

{
    return;
}

void hs_decrypt_none(void *mem, int size2, void *pass, int plen)

{
    return;
}

#elif defined(FAKE_ENCRYPT)

//#warning "Fake encryption, (simple XOR) for testing only"

// Just an XOR of the buffer to troubleshoot the interceptor

void hs_encrypt_fake(void *mem, int size2, void *pass, int plen)

{
    char *cmem = (char *)mem, *cpass = (char *) pass;

    //syslog(LOG_DEBUG,"hs_encrypt_fake size2=%d", size2);

    for(int loop = 0; loop < size2; loop += HS_BLOCK)
        {
        int block = MIN(HS_BLOCK, size2 - loop);

        //syslog(LOG_DEBUG,"hs_encrypt_fake block=%d", block);

        for(int aa = 0; aa < block; aa++)
            {
            cmem[loop + aa] = cmem[loop + aa] ^ 0xa4;
            //cmem[loop + aa] = cmem[loop + aa] ^ cpass[aa % plen];
            }
        }
}

void hs_decrypt_fake(void *mem, int size2, void *pass, int plen)

{
    char *cmem = (char *)mem, *cpass = (char *) pass;

    //syslog(LOG_DEBUG,"hs_decrypt_fake size2=%d", size2);

    for(int loop = 0; loop < size2; loop += HS_BLOCK)
        {
        int block = MIN(HS_BLOCK, size2 - loop);

        //syslog(LOG_DEBUG,"hs_decrypt_fake block=%d", block);

        for(int aa = 0; aa < block; aa++)
            {
            //cmem[loop + aa] = cmem[loop + aa] ^ cpass[aa % plen];
            cmem[loop + aa] = cmem[loop + aa] ^ 0xa4;
            }
        }
}

#elif defined(HALF_ENCRYPT)

//#warning "Half encryption, (simple XOR + pass XOR) for testing only"

// Just an XOR of the buffer and pass to troubleshoot the interceptor

void hs_encrypt_fake(void *mem, int size2, void *pass, int plen)

{
    char *cmem = (char *)mem, *cpass = (char *) pass;

    //syslog(LOG_DEBUG,"hs_encrypt_fake size2=%d", size2);

    for(int loop = 0; loop < size2; loop += HS_BLOCK)
        {
        int block = MIN(HS_BLOCK, size2 - loop);

        //syslog(LOG_DEBUG,"hs_encrypt_fake block=%d", block);

        for(int aa = 0; aa < block; aa++)
            {
            cmem[loop + aa] = cmem[loop + aa] ^ 0xa4;
            cmem[loop + aa] = cmem[loop + aa] ^ cpass[aa % plen];
            }
        }
}

void hs_decrypt_half(void *mem, int size2, void *pass, int plen)

{
    char *cmem = (char *)mem, *cpass = (char *) pass;

    //syslog(LOG_DEBUG,"hs_decrypt_fake size2=%d", size2);

    for(int loop = 0; loop < size2; loop += HS_BLOCK)
        {
        int block = MIN(HS_BLOCK, size2 - loop);

        //syslog(LOG_DEBUG,"hs_decrypt_fake block=%d", block);

        for(int aa = 0; aa < block; aa++)
            {
            cmem[loop + aa] = cmem[loop + aa] ^ cpass[aa % plen];
            cmem[loop + aa] = cmem[loop + aa] ^ 0xa4;
            }
        }
}

#else

// -----------------------------------------------------------------------
// HS crypt block loop. Extracted for the hsencfs project.

void hs_encrypt_org(void *mem, int size2, void *pass, int plen)

{
    int loop; char *pmem = (char*)mem;

    for(loop = 0; loop < size2; loop += HS_BLOCK)
        {
        int block = MIN(HS_BLOCK, size2 - loop);

        //syslog(LOG_DEBUG,"hs_encrypt_org block=%d", block);

        bluepoint2_encrypt(pmem, block, pass, plen);
        pmem += HS_BLOCK;
        }
}

void hs_decrypt_org(void *mem, int size2, void *pass, int plen)

{
    int loop; char *pmem = (char*)mem;

    for(loop = 0; loop < size2; loop += HS_BLOCK)
        {
        int block = MIN(HS_BLOCK, size2 - loop);

        //syslog(LOG_DEBUG,"hs_decrypt_org block=%d", block);

        bluepoint2_decrypt(pmem, block, pass, plen);
        pmem += HS_BLOCK;
        }
}

#endif

// EOF