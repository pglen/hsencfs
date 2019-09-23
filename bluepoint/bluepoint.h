//# -------------------------------------------------------------------------
//# Bluepoint encryption routines.
//#
//#   How it works:
//#
//#     Strings are walked chr by char with the loop:
//#         {
//#         $aa = ord(substr($_[0], $loop, 1));
//#         do something with $aa
//#         substr($_[0], $loop, 1) = pack("c", $aa);
//#         }
//#
//#   Flow:
//#         generate vector
//#         generate pass

//#         walk forward with password cycling loop
//#         walk backwards with feedback encryption
//#         walk forward with feedback encryption
//#
//#  The process guarantees that a single bit change in the original text
//#  will change every byte in the resulting block.
//#
//#  The bit propagation is such a high quality, that it beats current
//#  industrial strength encryptions.
//#
//#  Please see bit distribution study.
//#
//# -------------------------------------------------------------------------

typedef  unsigned long ulong;

void	bluepoint_encrypt(char *buff, int blen, char *pass, int plen);
void	bluepoint_decrypt(char *str, int slen, char *pass, int plen);
ulong   bluepoint_hash(char *buff, int blen);
ulong   bluepoint_crypthash(char *buff, int blen, char *pass, int plen);

#ifdef DEF_DUMPHEX
char 	*bluepoint_dumphex(char *str, int len);
#endif



