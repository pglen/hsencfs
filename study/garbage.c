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

    // Initialize OpenSSL
    //ERR_load_crypto_strings();
    //OpenSSL_add_all_algorithms();

    //int bufsize = 1000;
    //const void *buf = getSeedBuffer(bufsize);
    //RAND_seed(buf, bufsize);

    // Generate BIGNUM for public exponent
    bne = BN_new();
    if(!BN_set_word(bne, e)) {
        fprintf(stderr, "Error setting public exponent\n");
        goto cleanup;
    }

    // Generate RSA key pair
    rsa = RSA_new();
    if (!RSA_generate_key_ex(rsa, bits, bne, NULL)){
        fprintf(stderr, "Error generating RSA key\n");
        goto cleanup;
    }

    // Create BIO for writing PEM keys
    bio_private = BIO_new(BIO_s_mem());
    bio_public = BIO_new(BIO_s_mem());

    // Write private key to BIO
    if (!PEM_write_bio_RSAPrivateKey(bio_private, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error writing private key to BIO\n");
        goto cleanup;
    }

    // Write public key to BIO
    if (!PEM_write_bio_RSAPublicKey(bio_public, rsa)) {
        fprintf(stderr, "Error writing public key to BIO\n");
        goto cleanup;
    }

    // Get key lengths and allocate memory
    long private_len = BIO_ctrl(bio_private, BIO_CTRL_PENDING, 0, NULL);
    long public_len = BIO_ctrl(bio_public, BIO_CTRL_PENDING, 0, NULL);

    char *private_key_pem = (char *)malloc(private_len + 1);
    char *public_key_pem = (char *)malloc(public_len + 1);

    if (!private_key_pem || !public_key_pem) {
        fprintf(stderr, "Error allocating memory for keys\n");
        goto cleanup;
    }

    // Read key data from BIOs
    BIO_read(bio_private, private_key_pem, private_len);
    BIO_read(bio_public, public_key_pem, public_len);

    private_key_pem[private_len] = '\0';
    public_key_pem[public_len] = '\0';

    ret = 0;

    // Print or save the keys
    //printf("Private Key:\n%s\n", private_key_pem);
    //printf("Public Key:\n%s\n", public_key_pem);

    memcpy(privkey, private_key_pem, private_len);
    memcpy(pubkey,  public_key_pem, public_len);

    // Cleanup
cleanup:
    if(ret < 0)
        {
        printLastError("failed keygen  RSA");
        }
    //if (buf) free((void*)buf);
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

// EOF
