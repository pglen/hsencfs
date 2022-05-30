///////////////////////////////////////////////////////////////////////////
// Bluepoint block test suite
//

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

#include "stdio.h"

#include "../src/hsencfs.h"
#include "bluepoint2.h"
#include "hs_crypt.h"

#define DEF_DUMPHEX  1   // undefine this if you do not want bluepoint2_dumphex
//#include "bluepoint.h"
#include "bluepoint2.h"

struct centinel
{
    char sent1[5];
    char orig[4096];
    char sent2[5];

    char sent3[5];
    char copy[4096];
    char sent4[5];

    char sent5[5];
    char fake[4096];
    char sent6[5];
} cent;

char pass[128] = "1234";
int slen, plen;

int sdump(void *mem)
{
    int loop; char *cmem = (char*)mem;

    for(loop = 0; loop < 25; loop++)
        {
        printf("%02x ", cmem[loop] & 0xff);
        }
    printf("\n");
}

int main(int argc, char *argv[])

{
    int loop;

    for(loop = 0; loop < 4; loop++)
        {
        cent.sent1[loop] = loop + 'a';
        cent.sent2[loop] = loop + 'a';
        cent.sent3[loop] = loop + 'a';
        cent.sent4[loop] = loop + 'a';
        }

    cent.sent1[4] = 0;   cent.sent2[4] = 0;
    cent.sent3[4] = 0;   cent.sent4[4] = 0;

    memset(cent.orig, 0, sizeof(cent.orig));
    memset(cent.copy, 0, sizeof(cent.copy));

    slen = sizeof(cent.orig);
    plen = strlen(pass);

    //bluepoint2_set_functrace(1);
    //bluepoint2_set_verbose(1);

    memcpy(cent.copy, cent.orig, sizeof(cent.orig));

    sdump(cent.copy);
    // bluepoint2_encrypt(cent.copy, slen, pass, plen);
    //bluepoint2_encrypt(cent.fake, slen, pass, plen);

    hs_encrypt(cent.copy, slen, pass, plen);
    sdump(cent.copy);
    //strcpy(pass, "1235");

    //bluepoint2_decrypt(cent.copy, slen, pass, plen);
    hs_decrypt(cent.copy, slen, pass, plen);
    sdump(cent.copy);

    int ret = memcmp(cent.orig, cent.copy, sizeof(cent.orig));
    printf("Compare slen %d got %d\n", slen, ret);
    printf("Sentinels %4s, %4s, %4s, %4s\n", cent.sent1, cent.sent2, cent.sent3, cent.sent4);
}








