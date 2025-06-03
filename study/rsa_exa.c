//

#include <stdio.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

int padding = RSA_PKCS1_PADDING;

static unsigned long lasterr = 0;

void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    lasterr = ERR_get_error();
    ERR_error_string(lasterr, err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
}

RSA *createRSA(unsigned char * key, int public)
{
    RSA *rsa = NULL;
    BIO *keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
        {
        printf( "Failed to create key BIO");
        printLastError("create BIO");
        return rsa;
        }
    rsa = RSA_new();
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
        //printf( "Failed to create RSA");
        printLastError("failed create RSA");
        }
    //printf("RSA %p\n", rsa);
    return rsa;
}

const void* getSeedBuffer(int num)
{
    unsigned char *ret = malloc(num);
    for(int aa = 0; aa < num; aa++)
        ret[aa] = rand() & 0xff;
    return (const void*)ret;
}

int gen_keys(int bits, unsigned char *privkey, int privlen,
                unsigned char *pubkey, int publen)
{
    int ret = -1;
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    BIO *bio_private = NULL, *bio_public = NULL;
    unsigned long e = RSA_F4;  // Common public exponent (65537)
    //unsigned long e = RSA_3; // public exponent

    // Pre Clear it
    memset(privkey, '\0', privlen); memset(pubkey,'\0', publen);

    // 1. Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    int bufsize = 1000;
    const void *buf = getSeedBuffer(bufsize);
    RAND_seed(buf, bufsize);

    // 2. Generate BIGNUM for public exponent
    bne = BN_new();
    if(!BN_set_word(bne, e)) {
        fprintf(stderr, "Error setting public exponent\n");
        goto cleanup;
    }

    //if(!BN_one(bne)) {
    //    fprintf(stderr, "Error setting public exponent\n");
    //    goto cleanup;
    //}

    // 3. Generate RSA key pair
    rsa = RSA_new();
    //if (!RSA_generate_key(rsa, bits, bne, NULL)){
    if (!RSA_generate_key_ex(rsa, bits, bne, NULL)){
        fprintf(stderr, "Error generating RSA key\n");
        goto cleanup;
    }

    // 4. Create BIO for writing PEM keys
    bio_private = BIO_new(BIO_s_mem());
    bio_public = BIO_new(BIO_s_mem());

    // 5. Write private key to BIO
    if (!PEM_write_bio_RSAPrivateKey(bio_private, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error writing private key to BIO\n");
        goto cleanup;
    }

    // 6. Write public key to BIO
    if (!PEM_write_bio_RSAPublicKey(bio_public, rsa)) {
        fprintf(stderr, "Error writing public key to BIO\n");
        goto cleanup;
    }

    // 7. Get key lengths and allocate memory
    long private_len = BIO_ctrl(bio_private, BIO_CTRL_PENDING, 0, NULL);
    long public_len = BIO_ctrl(bio_public, BIO_CTRL_PENDING, 0, NULL);

    char *private_key_pem = (char *)malloc(private_len + 1);
    char *public_key_pem = (char *)malloc(public_len + 1);

    if (!private_key_pem || !public_key_pem) {
        fprintf(stderr, "Error allocating memory for keys\n");
        goto cleanup;
    }

    // 8. Read key data from BIOs
    BIO_read(bio_private, private_key_pem, private_len);
    BIO_read(bio_public, public_key_pem, public_len);

    private_key_pem[private_len] = '\0';
    public_key_pem[public_len] = '\0';

    ret = 0;

    // 9. Print or save the keys
    //printf("Private Key:\n%s\n", private_key_pem);
    //printf("Public Key:\n%s\n", public_key_pem);

    memcpy(privkey, private_key_pem, private_len);
    memcpy(pubkey,  public_key_pem, public_len);

    // 10. Cleanup
cleanup:
    if(ret < 0)
        {
        printLastError("failed keygen  RSA");
        }
    if (buf) free((void*)buf);
    if (rsa) RSA_free(rsa);
    if (bne) BN_free(bne);
    if (bio_private) BIO_free_all(bio_private);
    if (bio_public) BIO_free_all(bio_public);
    if (private_key_pem) free(private_key_pem);
    if (public_key_pem) free(public_key_pem);

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return ret;
}

int public_encrypt(unsigned char * data,int data_len,
                        unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 1);
    if (!rsa)
        return -1;
    printf("max size: %d\n", RSA_size(rsa));
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int private_decrypt(unsigned char * enc_data, int data_len,
                            unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 0);
    if (!rsa)
        return -1;
    int  result = RSA_private_decrypt(data_len,enc_data,
                                        decrypted,rsa,padding);
    return result;
}

int private_encrypt(unsigned char * data, int data_len,
                    unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    if (!rsa)
        return 0;
    int result = RSA_private_encrypt(data_len, data,
                                encrypted,rsa, padding);
    return result;
}

int public_decrypt(unsigned char * enc_data,int data_len,
                        unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    if (!rsa)
        return 0;
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

char publicKey2[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyzHfM+FO2qyTawXHsX26\n"\
"BHD8uTLzG5LI6WfkOJKaSdUxcnN3kHvRgUCYQF54PIa8P6OZ/Ff4TWLo+j+VS5fM\n"\
"mJDT86ZYHKZE8RchX6Qru3O1k2gyGbCy589ynTwsVpckdWHJedff7tMaQWtuWoMz\n"\
"0aCtnVx+k3X2CwEwNftFti1XCiOuFLpvssxOIUplN+TeF4ClwVLUGLdLp1KA3Vl6\n"\
"GnKaYJNum/IDzb4WVU6ZcfcmU1G9aHScQiStshbBsSSeL7MSISm9PQW5Rm3k3N4t\n"\
"uVXtqzDkbsZZJgFSZCaUdJzaYcGo7WPkk0jWvULNw+tjjb0oFj0Q/Ll+eQbs7op3\n"\
"+wIDAQAB\n"\
"-----END PUBLIC KEY-----\n"\
;

char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

 char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";


 char privateKey2[]="-----BEGIN PRIVATE KEY-----\n"\
"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDLMd8z4U7arJNr\n"\
"BcexfboEcPy5MvMbksjpZ+Q4kppJ1TFyc3eQe9GBQJhAXng8hrw/o5n8V/hNYuj6\n"\
"P5VLl8yYkNPzplgcpkTxFyFfpCu7c7WTaDIZsLLnz3KdPCxWlyR1Ycl519/u0xpB\n"\
"a25agzPRoK2dXH6TdfYLATA1+0W2LVcKI64Uum+yzE4hSmU35N4XgKXBUtQYt0un\n"\
"UoDdWXoacppgk26b8gPNvhZVTplx9yZTUb1odJxCJK2yFsGxJJ4vsxIhKb09BblG\n"\
"beTc3i25Ve2rMORuxlkmAVJkJpR0nNphwajtY+STSNa9Qs3D62ONvSgWPRD8uX55\n"\
"Buzuinf7AgMBAAECggEACn3wwIUJxVDT69rIjOmpCUGsSwPOecYCicrLhgBL5zQS\n"\
"8Y30xokeMEZdljVKkBWE8uRHtzfzoktRLFrMIrMb5WTVDOex9QjA1pITLxUTDQLU\n"\
"hWAD9j+hfUbA7E2HHJGBWG5MMPZsobBU0rvxXssXieN6E34LKyIUKk1NZ/wphVaK\n"\
"axl7PTkaPGac0YLh3EKHhvzJF5U2guLwu0ddEDEuYLqabTYrwvv4+Y80ND1+tl+z\n"\
"prSJ9sLOiEIZhfR97BkKVcZE42DTtjSB+vRYApma0yJEPL2jWb0J78Yj0aWeaWZe\n"\
"SOShNsvFmC1ZbVDtArROOwXseE67i6XDnYjIg8W/wQKBgQDvfx+2RF7oV/Twd8nP\n"\
"YI0BQCnRaEIhli/tMbm2Rktl7iAZx+MSvNvSeEvdCJkvnTqBHAqTxDrg2uuhggpX\n"\
"a5Q8+V0/zpBtoYxcEleu9nRKQPcn86Yavg21d3jad0BLnI4UNsDfHmYrNoh58FAT\n"\
"EFfG+I6KXX8XwBzKn3q/vlH+zQKBgQDZMlxz+mSlzcPoPmeEWvHnA8w7gb3tz+J7\n"\
"Cd0nOCvXgi/EZJiuslJpzd4eaQZJdnINblY99/zPv4jMoy/UIyVgslsRI5DoMPEu\n"\
"Cdl3V3bK51eOuAFmfAoQQPxlLicJX0LYYUAszWdNVnoJr7h0OTn4n8LtvfJVpwdG\n"\
"DxPjnUnB5wKBgFyq5YxS3B4umlnJH88b3rNTLlsWajAwuo6epOsAPABOqSEQlK4V\n"\
"YUEIxuHZh9xCi/aU8QrH7LhAPNgbRwEYYR1Op2Qe+wdQcMzXVBIgzlJE3N0ai3Th\n"\
"gNBsT9jIN5qKEveDUBGE46dozFnSQEmAE1arqgujrZ90+C72kjpK29MpAoGAQ4t6\n"\
"3wKGnF2SSD5n+OxDgGFY+USO6U8WEsdthE3erIWrDzttlB6WrJq+MdzdfKkeLPkc\n"\
"Tuc5Mu5Qv7scG6/WZuzwjzLtVJgr2PJtM8T6h31MaHDm1pVKl+Vt2JVyxGJgqmQM\n"\
"DiLOtmlnSG3iQhqt4ZjliQPiQirQg0QbHlUC5A8CgYBRsdydsvwiUU6V2WT8mT0d\n"\
"lzqDV+bbVcDvnXsz/BqgZwt/od0aZhjYIXrTzqTR0A5LqqSHgw2C7Kr0AgI/hdiQ\n"\
"MFrL1lrAArfei6o/0AnBvafW61gl14gAPa5V6h6oVHUuS6dOiB/SeHw21zVToWuw\n"\
"vcQ7aOUKOU4VJGch7JIx3w==\n"\
"-----END PRIVATE KEY-----\n"\
;

//key length : 2048

char plainText[2048/8] = "\
Hello this is a text this is a text this is a text this is a text.\n\
Hello this is a text this is a text this is a text this is a text.\n\
Hello this is a text this is a text this is a text this is a text.\
";

void hexdump(char *ptr, int len)
{
    int llen = 24;
    for (int aa = 0; aa < len; aa++)
        {
        unsigned char chh = ptr[aa] & 0xff;
        if(chh > 127 || chh < 32)
            printf("%.2x ", chh);
        else
            printf(" %c ", chh);

        if (aa % llen == llen-1)
            printf("\n");
        }
}

unsigned char  encrypted[4098]={};
unsigned char  decrypted[4098]={};

unsigned char privkey[4098] = {};
unsigned char pubkey[4098] = {};

int main(){

    //printf("'\n%s\n'", privateKey);
    //printf("'\n%s\n'", publicKey);
    //exit(0);

    int ret = gen_keys(2048, privkey, sizeof(privkey),
                            pubkey, sizeof(pubkey));
    if (ret < 0)
        {
        printf("error on generate keys\n");
        exit(1);
        }
    //printf("'\n%s\n'", privkey);
    printf("'\n%s\n'", pubkey);
    //exit(0);

    // Create keys on the fly
    printf("original Text: \n%s\n", plainText);

    int encrypted_length = public_encrypt(plainText,
                            //strlen(plainText), pubkey, encrypted);
                            strlen(plainText), publicKey2, encrypted);
    if(encrypted_length == -1)
    {
        printLastError("Public Encrypt failed ");
        //printLastError("encrypt  RSA");
        exit(0);
    }

    printf("Encrypted length: %d\n",encrypted_length);
    //printf("Encrypted Text: \n%s\n", encrypted);
    hexdump(encrypted, encrypted_length);

    int decrypted_length = private_decrypt(encrypted,
                            //encrypted_length, privkey, decrypted);
                            encrypted_length, privateKey2, decrypted);

    if(decrypted_length == -1)
    {
        printLastError("Private Decrypt failed");
        exit(0);
    }

    printf("\nDecrypted Text: \n%s\n", decrypted);

    //printf("Decrypted Length %d\n",decrypted_length);
    //encrypted_length= private_encrypt(plainText,
    //            strlen(plainText),privateKey,encrypted);
    //if(encrypted_length == -1)
    //{
    //    printLastError("Private Encrypt failed");
    //    exit(0);
    //}
    //printf("Encrypted length =%d\n",encrypted_length);
    //decrypted_length = public_decrypt(encrypted,
    //                  encrypted_length,publicKey, decrypted);
    //if(decrypted_length == -1)
    //{
    //    printLastError("Public Decrypt failed");
    //    exit(0);
    //}
    //printf("Decrypted Text =%s\n",decrypted);
    //printf("Decrypted Length =%d\n",decrypted_length);
    //

    return 0;
    }

//# EOF
