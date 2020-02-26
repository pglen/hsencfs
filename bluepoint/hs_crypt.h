// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//

// High security block encryption

#define HS_BLOCK 4096

#ifndef MIN
#define MIN(a, b) (a) > (b) ? (b) : (a)
#endif

// This is used for testing ONLY
// NO NO  define FAKE

#ifdef FAKE

// Make sure the maintainer knows this is a NO NO
//#pragma GCC error "This is for testing only. DO NOT ENABLE"

#define     hs_encrypt  hs_encrypt_fake
#define     hs_decrypt  hs_decrypt_fake

void hs_encrypt_fake(void *mem, int size2, void *pass, int plen);
void hs_decrypt_fake(void *mem, int size2, void *pass, int plen);

#else

// Deploy the real encryption

#define     hs_encrypt  hs_encrypt_org
#define     hs_decrypt  hs_decrypt_org

void hs_encrypt_org(void *mem, int size2, void *pass, int plen);
void hs_decrypt_org(void *mem, int size2, void *pass, int plen);

#endif


// EOF




