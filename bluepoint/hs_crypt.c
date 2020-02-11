// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//

#include "hs_crypt.h"

// -----------------------------------------------------------------------
// HS crypt block loop. Extracted for the hsencfs project.

void hs_encrypt_org(void *mem, int size2, void *pass, int plen)

{
    int loop; char *pmem = (char*)mem;

    for(loop = 0; loop < size2; loop += HS_BLOCK)
        {
        int block = MIN(HS_BLOCK, size2 - loop);
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
        bluepoint2_decrypt(pmem, block, pass, plen);
        pmem += HS_BLOCK;
        }
}

#ifdef FAKE

// Just an XOR of the buffer to troubleshoot the interceptor

void hs_encrypt_fake(void *mem, int size2, void *pass, int plen)

{
    char *cmem = (char *)mem, *cpass = (char *) pass;

    for(int aa = 0; aa < size2; aa++)
        {
        cmem[aa] = cmem[aa] ^ 2;
        cmem[aa] = cmem[aa] ^ cpass[aa % plen];
        cmem[aa] = cmem[aa] ^ (aa % 200);
        }
}

void hs_decrypt_fake(void *mem, int size2, void *pass, int plen)

{
    char *cmem = (char *)mem, *cpass = (char *) pass;
    for(int aa = 0; aa < size2; aa++)
        {
        cmem[aa] = cmem[aa] ^ (aa % 200);
        cmem[aa] = cmem[aa] ^ cpass[aa % plen];
        cmem[aa] = cmem[aa] ^ 2;
        }
}

#endif

// EOF




