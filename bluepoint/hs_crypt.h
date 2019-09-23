
//#ifndef HS_BLOCK
//#define HS_BLOCK 4096
//#endif

#ifndef MIN
#define MIN(a, b) (a) > (b) ? (b) : (a)
#endif

void hs_encrypt(void *mem, int size2, void *pass, int plen);
void hs_decrypt(void *mem, int size2, void *pass, int plen);



