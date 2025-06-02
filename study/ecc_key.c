#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>

void generate_ecc_keys() {
    EC_KEY *ec_key = EC_KEY_new();
    if (!ec_key) {
        fprintf(stderr, "Error creating EC_KEY object\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    int curve_nid = OBJ_sn2nid("prime256v1");  // Or "secp384r1"
    if (curve_nid == NID_undef) {
        fprintf(stderr, "Error: Curve not found.\n");
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        return;
    }

    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(curve_nid);
    if (!ec_group) {
        fprintf(stderr, "Error creating EC_GROUP object\n");
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        return;
    }

    if (EC_KEY_set_group(ec_key, ec_group) != 1) {
        fprintf(stderr, "Error setting EC_GROUP to EC_KEY\n");
        ERR_print_errors_fp(stderr);
        EC_GROUP_free(ec_group);
        EC_KEY_free(ec_key);
        return;
    }
    EC_GROUP_free(ec_group);


    if (EC_KEY_generate_key(ec_key) != 1) {
        fprintf(stderr, "Error generating EC key\n");
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        return;
    }

    FILE *private_key_file = fopen("private.pem", "wb");
    if (!private_key_file) {
        fprintf(stderr, "Error opening private key file\n");
        EC_KEY_free(ec_key);
        return;
    }
    PEM_write_ECPrivateKey(private_key_file, ec_key, NULL, NULL, 0, NULL, NULL);
    fclose(private_key_file);

    FILE *public_key_file = fopen("public.pem", "wb");
    if (!public_key_file) {
        fprintf(stderr, "Error opening public key file\n");
        EC_KEY_free(ec_key);
        return;
    }
    PEM_write_EC_PUBKEY(public_key_file, ec_key);
    fclose(public_key_file);

    printf("ECC keys generated successfully!\n");
    EC_KEY_free(ec_key);
}

int main() {
    generate_ecc_keys();
    return 0;
}

