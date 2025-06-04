//

#include <stdio.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define MIN(aa, bb) aa > bb ? bb : aa
typedef unsigned char uchar;

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static int pad = RSA_PKCS1_PADDING;
static const char *propq = NULL;

static void hexdump(char *ptr, int len)
{
    int llen = 24;
    for (int aa = 0; aa < len; aa++)
        {
        uchar chh = ptr[aa] & 0xff;
        if(chh > 127 || chh < 32)
            printf("%.2x ", chh);
        else
            printf(" %c ", chh);

        if (aa % llen == llen-1)
            printf("\n");
        }
}

static void printLastError(char *msg)
{
    ERR_load_crypto_strings();
    char *err = malloc(130);;
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
}

static char* publicKeyToString(EVP_PKEY* pubKey, char *out, int maxlen)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pubKey);
    char* pem_str;
    long len = BIO_get_mem_data(bio, &pem_str);
    len = MIN(len, maxlen);
    memcpy(out, pem_str, len);
    out[len] = '\0';
    BIO_free(bio);
    return out;
}

static char* privateKeyToString(EVP_PKEY* Key, char *out, int maxlen)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, Key, NULL, NULL, 0, NULL, NULL);
    char* pem_str;
    long len = BIO_get_mem_data(bio, &pem_str);
    len = MIN(len, maxlen);
    memcpy(out, pem_str, len);
    out[len] = '\0';
    BIO_free(bio);
    return out;
}

/*
 * Generates an RSA public-private key pair and returns it.
 * The number of bits is specified by the bits argument.
 *
 * This uses the long way of generating an RSA key.
 */

static EVP_PKEY *generate_rsa_key(unsigned int bits)
{
    EVP_PKEY_CTX *genctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned int primes = 2;
    OSSL_LIB_CTX *libctx = NULL;

    /* Create context using RSA algorithm. "RSA-PSS" could also be used here. */
    genctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", propq);
    if (genctx == NULL) {
        printLastError("EVP_PKEY_CTX_new_from_name() failed");
        goto cleanup;
    }

    /* Initialize context for key generation purposes. */
    if (EVP_PKEY_keygen_init(genctx) <= 0) {
        printLastError("EVP_PKEY_keygen_init() failed");
        goto cleanup;
    }

    /*
     * Here we set the number of bits to use in the RSA key.
     * See comment at top of file for information on appropriate values.
     */
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, bits) <= 0) {
        printLastError("EVP_PKEY_CTX_set_rsa_keygen_bits() failed");
        goto cleanup;
    }

    /*
     * It is possible to create an RSA key using more than two primes.
     * Do not do this unless you know why you need this.
     * You ordinarily do not need to specify this, as the default is two.
     *
     * Both of these parameters can also be set via EVP_PKEY_CTX_set_params, but
     * these functions provide a more concise way to do so.
     */
    if (EVP_PKEY_CTX_set_rsa_keygen_primes(genctx, primes) <= 0) {
        printLastError("EVP_PKEY_CTX_set_rsa_keygen_primes() failed");
        goto cleanup;
    }

    /*
     * Generating an RSA key with a number of bits large enough to be secure for
     * modern applications can take a fairly substantial amount of time (e.g.
     * one second). If you require fast key generation, consider using an EC key
     * instead.
     *
     * If you require progress information during the key generation process,
     * you can set a progress callback using EVP_PKEY_set_cb; see the example in
     * EVP_PKEY_generate(3).
     */
    if (EVP_PKEY_generate(genctx, &pkey) <= 0) {
        printLastError("EVP_PKEY_generate() failed");
        goto cleanup;
    }
cleanup:
    EVP_PKEY_CTX_free(genctx);
    /* pkey object is the generated key pair. */
    return pkey;
}

static  RSA *createRSA(uchar *key, int public)
{
    BIO *keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
        {
        printLastError("failed create BIO");
        return NULL;
        }
    RSA *rsa = RSA_new();
    if(public)
        {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
        }
    else
        {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
        }
    if(rsa == NULL)
        {
        printLastError("failed ot create RSA");
        }
    return rsa;
}

int public_encrypt(uchar *data, int data_len, uchar *key, uchar *ebuf)
{
    RSA *rsa = createRSA(key, 1);
    if (!rsa)
        return -1;

    int maxlen = RSA_size(rsa);
    //printf("maxlen: %d\n", maxlen);
    if (data_len > maxlen)
        {
        RSA_free(rsa);
        printf("Cannot encrypt. (too long) %d\n", data_len);
        return -1;
        }
    int result = RSA_public_encrypt(data_len, data, ebuf, rsa, pad);
    RSA_free(rsa);
    return result;
}

int private_decrypt(uchar * enc_data, int data_len, uchar *key, uchar *dbuf)
{
    RSA *rsa = createRSA(key, 0);
    if (!rsa)
        return -1;
    int  result = RSA_private_decrypt(data_len, enc_data,
                                        dbuf, rsa, pad);
    RSA_free(rsa);
    return result;
}

int     private_encrypt(uchar * data, int data_len, uchar *key, uchar *ebuf)
{
    RSA *rsa = createRSA(key,0);
    if (!rsa)
        return 0;
    int result = RSA_private_encrypt(data_len, data, ebuf,rsa, pad);
    RSA_free(rsa);
    return result;
}

int     public_decrypt(uchar * enc_data,int data_len, uchar *key, uchar *dbuf)
{
    RSA *rsa = createRSA(key, 1);
    if (!rsa)
        return 0;
    int  result = RSA_public_decrypt(data_len, enc_data, dbuf, rsa, pad);
    RSA_free(rsa);
    return result;
}

char ptext[] = "\
Hello this is a text this is a text this is a text this is a text.\n\
Hello this is a text this is a text this is a text this is a text.\n\
Hello this is a text this is a text this is a text this is a text.\
";

uchar   ebuf[1024]={};
uchar   dbuf[1024]={};

uchar   privkey[2000] = {};
uchar   pubkey[1000] = {};

unsigned int bits = 2048;
EVP_PKEY *pkey = NULL;

int main(int argc, char *argv[])
{
    //printf("max encryption size: %d\n", RSA_size(rsa));
    pkey = generate_rsa_key(bits);

    char *ss = publicKeyToString(pkey, pubkey, sizeof(pubkey));
    //printf("String: '%s'\n", ss);

    char *pss = privateKeyToString(pkey, privkey, sizeof(privkey));
    //printf("String: '%s'\n", pss);

    //printf("privlen: %ld publen: %ld\n",  strlen(privkey), strlen(pubkey));
    //printf("'\n%s\n'", privkey);
    //printf("'\n%s\n'", pubkey);

    printf("Org len: %ld\n", strlen(ptext));
    // Create keys on the fly
    printf("Orig text:\n%s\n", ptext);

    int elen = public_encrypt(ptext, strlen(ptext), pubkey, ebuf);
    if(elen == -1)
        {
        printLastError("encrypt  RSA");
        exit(1);
        }

    printf("buf length: %d\n", elen);
    //hexdump(ebuf, elen);
    int dlen = private_decrypt(ebuf, elen, privkey, dbuf);
    if(dlen == -1)
        {
        printLastError("private decrypt failed");
        exit(1);
        }
    printf("dbuf Text: \n'%s'\n", dbuf);

    // ----------------------------------------------------------
    // Reverse mode

    //printf("\ndbuf Text: \n%s\n", dbuf);
    //printf("dbuf Length %d\n", dlen);
    elen = private_encrypt(ptext, strlen(ptext), privkey, ebuf);
    if(elen == -1)
        {
        printLastError("private encrypt failed");
        exit(1);
        }
    //printf("ebuf length: %d\n", elen);
    dlen = public_decrypt(ebuf, elen, pubkey, dbuf);
    if(dlen == -1)
        {
        printLastError("public Ddecrypt failed");
        exit(1);
        }
    printf("dbuf Text: \n'%s'\n", dbuf);
    //printf("dbuf Length %d\n",dlen);

    exit(0);
    }

//# EOF
