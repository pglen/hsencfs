///////////////////////////////////////////////////////////////////////////
// Bluepoint test suite
///////////////////////////////////////////////////////////////////////////

#include "stdlib.h"
#include "stdio.h"
#include "string.h"

#define DEF_DUMPHEX  1   // undefine this if you do not want bluepoint2_dumphex
#include "bluepoint2.h"

char copy[128] = "";
char orig[128] = "abcdefghijklmnopqrstuvwxyz";
char pass[128] = "1234";

int main(int argc, char *argv[])

{
    long hh;

    strncpy(copy, orig, sizeof(copy));

    if(argc > 1)
        {
        //printf("argv[1]=%s\n", argv[1]);
        strncpy(orig, argv[1], sizeof(orig));
        strncpy(copy, argv[1], sizeof(copy));
        }

    if(argc > 2)
        {
        //printf("argv[2]=%s\n",argv[2]);
        strncpy(pass, argv[2], sizeof(pass));
        }

    printf("orignal='%s' pass='%s'\n", orig, pass);

    int slen = strlen(orig); int plen = strlen(pass);

    bluepoint2_encrypt(orig, slen, pass, plen);

    printf("ENCRYPTED: \n");
    printf("%s", bluepoint2_dumphex(orig, slen));
    printf("\nEND ENCRYPTED\n");

    printf("HASH:\n");
    hh = bluepoint2_hash(copy, slen);
    printf("%u 0x%08x\n", hh, hh);

    printf("CRYPTHASH: \n");
    hh = bluepoint2_crypthash(copy, slen, pass, plen);
    printf("%u 0x%08x\n", hh, hh);

    printf("HASH64:\n");
    unsigned long long int hhh = bluepoint2_hash64(copy, slen);
    printf("%llu 0x%llx\n", hhh, hhh);

    printf("CRYPTHASH64: \n");
    hhh = bluepoint2_crypthash64(copy, slen, pass, plen);
    printf("%llu 0x%llx\n", hhh, hhh);

    char   dumped[256];
    memset(dumped, 'x', sizeof(dumped));
    int olen = sizeof(dumped);

    bluepoint2_tohex(orig, slen, dumped, &olen);

    printf("TOHEX: \n");
    printf("'%s'", dumped);
    printf("\nEND TOHEX\n");

    char   dumped2[256];
    memset(dumped2, 'y', sizeof(dumped2));
    int olen2 = sizeof(dumped2);
    bluepoint2_fromhex(dumped, olen, dumped2, &olen2);
    if (memcmp(dumped2, orig, olen2))
        {
        printf("Decrypt error.");
        } 
    printf("FROMHEX: \n");
    //printf("'%s'", dumped2);
    printf("%s", bluepoint2_dumphex(dumped2, olen2));
    printf("\nEND FROMHEX\n");

    bluepoint2_decrypt(dumped2, olen2, pass, plen);
    printf("decrypted='%s'\n", dumped2);
}


