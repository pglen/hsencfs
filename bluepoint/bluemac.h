//# Use these macros as a stack. On decrypt, make the order the reverse
//# of the crypt process.
//#
//# Example: pass(+)-fw(+)-bw(+) +++ will be +++ bw(-)-fw(-)-pass(-)
//#

#define HECTOR(op)                                  \
    loop2 = 0;                                      \
    for (loop = 0; loop < slen; loop++)             \
        {                                           \
        aa = str[loop];                             \
        aa = aa op hector[loop2];                   \
        loop2++;                                    \
        if(loop2 >= sizeof(hector)) {loop2 = 0;}    \
        str[loop] = aa;                             \
        }

#define PASSLOOP(op)                                \
    loop2 = 0;                                      \
    for (loop = 0; loop < slen; loop++)             \
        {                                           \
        aa = str[loop];                             \
        aa = aa op pass[loop2];                     \
        loop2++;                                    \
        if(loop2 >= plen) {loop2 = 0;}              \
        str[loop] = aa;                             \
        }

#define FWLOOP(op)                                  \
    bb = 0;                                         \
    for (loop = 0; loop < slen; loop++)             \
        {                                           \
        aa = str[loop];                             \
        aa ^= forward;                              \
        aa  += addend;                              \
        aa  += bb;                                  \
        aa = ROTATE_CHAR_RIGHT(aa, 3);              \
        bb = aa;                                    \
        str[loop] = aa;                             \
        }                                           \

#define FWLOOP2(op)                                 \
    cc = 0;                                         \
    for (loop = 0; loop < slen; loop++)             \
        {                                           \
        bb = cc;                                    \
        cc = aa = str[loop];                        \
        aa = ROTATE_CHAR_LEFT(aa, 3);               \
        aa -=  bb;                                  \
        aa -= addend;                               \
        aa ^= forward;                              \
        str[loop] = aa;                             \
        }

#define BWLOOP(op)                                  \
    bb = 0;                                         \
    for (loop = slen-1; loop >= 0; loop--)          \
        {                                           \
        aa = str[loop];                             \
        aa ^= backward;                             \
        aa = aa op addend;                          \
        aa = aa op bb;                              \
        bb = aa;                                    \
        str[loop] = aa;                             \
        }                                           \

  #define BWLOOP2(op)                               \
    cc = 0;                                         \
    for (loop = slen-1; loop >= 0; loop--)          \
        {                                           \
        bb = cc;                                    \
        aa = cc = str[loop];                        \
                                                    \
        aa = aa op bb;                              \
        aa = aa op addend;                          \
        aa ^= backward;                             \
        str[loop] = aa;                             \
        }                                           \

#define MIXIT(op)                                   \
    for (loop = 0; loop < slen/2; loop++)           \
        {                                           \
        aa = str[loop];                             \
        bb = str[(slen-1) - loop];                  \
        aa = aa op bb;                              \
        str[loop] = aa;                             \
        }                                           \

#define MIXITR(op)                                  \
    loop2 = slen / 2;                               \
    for (loop = loop2; loop < slen; loop++)         \
        {                                           \
        aa = str[loop];                             \
        bb = str[loop - loop2];                     \
        aa = aa op bb;                              \
        str[loop] = aa;                             \
        }                                           \

#define MIXIT2(op)                                  \
    for (loop = 0; loop < slen/2; loop++)           \
        {                                           \
        aa = str[loop];                             \
        bb = str[loop + slen/2];                    \
        aa = aa op bb;                              \
        str[loop] = aa;                             \
        }                                           \

#define MIXIT2R(op)                                 \
    for (loop = slen/2; loop < slen; loop++)        \
        {                                           \
        aa = str[loop];                             \
        bb = str[loop - slen/2];                    \
        aa = aa op bb;                              \
        str[loop] = aa;                             \
        }                                           \

#define MIXIT4(op)                                  \
    for (loop = 0; loop < slen/4; loop++)           \
        {                                           \
        aa = str[loop];                             \
        bb = str[loop + slen/2];                    \
        aa = aa op bb;                              \
        str[loop] = aa;                             \
        }                                           \



