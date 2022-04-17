// -----------------------------------------------------------------------
//
// HSENCFS (High Security EnCrypting File System)
//

// High security block encryption

#include "bluepoint2.h"

#define HS_BLOCK 4096

#ifndef MIN
#define MIN(a, b) (a) > (b) ? (b) : (a)
#endif

// Warning: this will disable all encryptions;
// This is used for testing ONLY;

//   define FAKE
//   define NONE

// -----------------------------------------------------------------------
// Test cases for simplifying and / or disabling encryption
// Nothing defined activates the real encryption

//#define NONE_ENCRYPT  1
//#define FAKE_ENCRYPT    1
#define FULL_ENCRYPT  1

#if defined(NONE_ENCRYPT) && defined(FAKE_ENCRYPT)
    #error "Cannot define more than one. of NONE or FAKE"
#endif

#if defined(NONE_ENCRYPT) && defined(FULL_ENCRYPT)
    #error "Cannot define more than one. of NONE or FULL"
#endif

#if defined(FAKE_ENCRYPT) && defined(FULL_ENCRYPT)
    #error "Cannot define more than one. of FAKE or FULL"
#endif


#ifdef NONE_ENCRYPT

// Make sure the maintainer knows this is a NO NO
//#pragma GCC error "This is for testing only. DO NOT ENABLE"

#define     hs_encrypt  hs_encrypt_none
#define     hs_decrypt  hs_decrypt_none

void hs_encrypt_none(void *mem, int size2, void *pass, int plen);
void hs_decrypt_none(void *mem, int size2, void *pass, int plen);

#elif defined(FAKE_ENCRYPT)

// Make sure the maintainer knows this is a NO NO
//#pragma GCC error "This is for testing only. DO NOT ENABLE"

#define     hs_encrypt  hs_encrypt_fake
#define     hs_decrypt  hs_decrypt_fake

void hs_encrypt_fake(void *mem, int size2, void *pass, int plen);
void hs_decrypt_fake(void *mem, int size2, void *pass, int plen);

#elif defined(FULL_ENCRYPT)

// Deploy the real encryption

#define     hs_encrypt  hs_encrypt_org
#define     hs_decrypt  hs_decrypt_org

void hs_encrypt_org(void *mem, int size2, void *pass, int plen);
void hs_decrypt_org(void *mem, int size2, void *pass, int plen);

#else

#define     hs_encrypt  hs_encrypt_undef
#define     hs_decrypt  hs_decrypt_undef

#error "Must define encryption type: FAKE NONE FULL"

void hs_encrypt_undef(void *mem, int size2, void *pass, int plen) {};
void hs_decrypt_undef(void *mem, int size2, void *pass, int plen) {};

#endif


// EOF