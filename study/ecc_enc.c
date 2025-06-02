
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>

void hexdump(char *ptr, int len)
{
    for (int aa = 0; aa < len; aa++)
        printf("%c ", ptr[aa] & 0xff);
}

int EncryptString(
    char *InStr, int Len, char *InPub, char* OutStr, int Olen)
{
    // Load key
    FILE* f = fopen(InPub, "r");
    EVP_PKEY* pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    //EVP_PKEY* pkey = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    //hexdump((char*)*((char*)pkey), 32);
    // Create/initialize context
    EVP_PKEY_CTX* ctx;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);

    // Specify padding: default is PKCS#1 v1.5
    // EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING); // for OAEP with SHA1 for both digests

    // Encryption
    size_t ciphertextLen;
    EVP_PKEY_encrypt(ctx, NULL, &ciphertextLen, (const unsigned char*)InStr, Len);
    printf("clen %ld\n",ciphertextLen);
    unsigned char* ciphertext = (unsigned char*)OPENSSL_malloc(ciphertextLen);
    EVP_PKEY_encrypt(ctx, ciphertext, &ciphertextLen, (const unsigned char*)InStr, Len);
    //hexdump(ciphertext, ciphertextLen);
    memcpy(OutStr, ciphertext, ciphertextLen);
    // Release memory
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(ciphertext);

    return true; // add exception/error handling
}

int DecryptString(
    char *InStr, int Len, char *InPri, char* OutStr, int Olen)
{
    EVP_PKEY_CTX *ctx;
    unsigned char *out, *in;
    size_t outlen, inlen;

    /* NB: assumes key in, inlen are already set up
     * and that key is an RSA private key
     */

    FILE* f = fopen(InPri, "r");
    EVP_PKEY* pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        { printf("EVP_PKEY_CTX_new\n "); return 0;  }
           /* Error occurred */
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        printf("EVP_PKEY_decrypt_init\n ");
           /* Error */

    //if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_OAEP_PADDING) <= 0)
    //       /* Error */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_X931_PADDING) <= 0)
        printf("EVP_PKEY_CTX_set_rsa_padding \n");
           /* Error */

    /* Determine buffer length */
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
        printf("EVP_PKEY_decrypt\n");
           /* Error */

    printf("clen %ld\n", outlen);
    out = OPENSSL_malloc(outlen);

    if (!out)
        printf("cannot alloc");
        /* malloc failure */

    if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
        printf("EVP_PKEY_decrypt alloc");

    hexdump(out, outlen);
    /* Decrypted data is outlen bytes written to buffer out */
}

char instr[] = "hello";
char outstr[3000];
char outstr2[3000];

int main(int argc, char *argv)
{
    EncryptString(instr, strlen(instr), "public.pem",
             outstr, sizeof(outstr));

    printf("outstr: '%s'\n", outstr);

    DecryptString(outstr, strlen(outstr), "private.pem",
             outstr2, sizeof(outstr2));

    printf("outstr2: '%s'\n", outstr2);

    return 0;
}

// EOF
