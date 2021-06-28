// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//

#include "hs_crypt.h"
#include <syslog.h>

#ifdef NONE

#warning "None encryption, for testing only"

void hs_encrypt_none(void *mem, int size2, void *pass, int plen)

{
    return;
}

void hs_decrypt_none(void *mem, int size2, void *pass, int plen)

{
    return;
}

#elif defined(FAKE)

#warning "Fake encryption, for testing only"

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
            cmem[loop + aa] = cmem[loop + aa] ^ 0x80;
            //cmem[loop + aa] = cmem[loop + aa] ^ cpass[loop + aa % plen];
            //cmem[loop + aa] = cmem[loop + aa] ^ (loop + aa % 200);
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
            //cmem[loop + aa] = cmem[loop + aa] ^ (loop + aa % 200);
            //cmem[loop + aa] = cmem[loop + aa] ^ cpass[loop + aa % plen];
            cmem[loop + aa] = cmem[loop + aa] ^ 0x80;
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