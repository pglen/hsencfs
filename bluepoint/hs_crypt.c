
#include "hs_crypt.h"

// -----------------------------------------------------------------------
// HS crypt block loop. Extracted for the hsencfs project.

void hs_encrypt(void *mem, int size2, void *pass, int plen)

{
    int loop; char *pmem = (char*)mem;

    for(loop = 0; loop < size2; loop += HS_BLOCK)
        {
        int block = MIN(HS_BLOCK, size2 - loop);
        bluepoint2_encrypt(pmem, block, pass, plen);
        pmem += HS_BLOCK;
        }
}

void hs_decrypt(void *mem, int size2, void *pass, int plen)

{
    int loop; char *pmem = (char*)mem;

    for(loop = 0; loop < size2; loop += HS_BLOCK)
        {
        int block = MIN(HS_BLOCK, size2 - loop);
        bluepoint2_decrypt(pmem, block, pass, plen);
        pmem += HS_BLOCK;
        }
}








