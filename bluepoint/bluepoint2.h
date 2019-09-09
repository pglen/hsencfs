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

int	bluepoint2_encrypt(char *buff, int blen, char *pass, int plen);
int	bluepoint2_decrypt(char *str, int slen, char *pass, int plen);

ulong   bluepoint2_hash(char *buff, int blen);
ulong   bluepoint2_crypthash(char *buff, int blen, char *pass, int plen);

// New Hashes:

unsigned long long bluepoint2_hash64(char *buff, int blen);
unsigned long long bluepoint2_crypthash64(char *buff, int blen, char *pass, int plen);

// These return the same buffer, move data before second call

char    *bluepoint2_dumphex(char *str, int len);
char    *bluepoint2_dump(char *str, int len);
char    *bluepoint2_undump(char *str, int len);

// Convert to a friendly format:

char    *bluepoint2_tohex(char *str, int len, char *out, int *olen);
char    *bluepoint2_fromhex(char *str, int len, char *out, int *olen);

// Helpers

int     bluepoint2_set_verbose(int flag);
int     bluepoint2_set_functrace(int flag);
int     bluepoint2_set_debug(int flag);

// Encryption modifiers

int     bluepoint2_set_rounds(int xrounds);

// High security block encryption

#define HS_BLOCK 1024

void hs_encrypt(void *mem, int size2, void *pass, int plen);
void hs_decrypt(void *mem, int size2, void *pass, int plen);

// EOF



