
/* =====[ project ]========================================================

   File Name:       hsutils.h

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Wed 07.Jul.2021      Peter Glen      Initial version.
      0.00  Tue 12.Apr.2022      Peter Glen      Reworked for virtual

   ======================================================================= */

// Define these so we do not include the main header
// This way the compiler filters out global variable  access

#ifndef FALSE
#define FALSE (0==1)
#endif
#ifndef TRUE
#define TRUE  (0==0)
#endif

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

typedef unsigned int  uint;
typedef unsigned char uchar;

// Warning: this will disable all encryptions;
// This is used for testing ONLY;

// -----------------------------------------------------------------------
// Test cases for simplifying and / or disabling encryption
// Nothing defined yields error
// FULL_ENCRYPT activates the real encryption

//#define NONE_ENCRYPT      1
//#define FAKE_ENCRYPT    1
//#define HALF_ENCRYPT    1
#define FULL_ENCRYPT    1

//# EOF

