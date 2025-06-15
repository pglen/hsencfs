
/* =====[ base64.h ]=====================================================

   File Name:       base64.h

   Description:

   Revisions:

      REV       DATE                BY           DESCRIPTION
      ----  ---------------      ----------      -------------------------
      0.00  Sun 15.Jun.2025      Peter Glen      Initial version.

   ======================================================================= */

char *base64_encode(const unsigned char *data,
                            size_t input_length,
                                size_t *output_length) ;

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                                size_t *output_length);

// EOF
