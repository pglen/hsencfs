#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <stdio.h>

int main() {
    // 1. Select a curve (e.g., secp256k1)
    EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!curve) {
        fprintf(stderr, "Failed to create curve.\n");
        return 1;
    }

    // 2. Generate private key
    BIGNUM *privateKey = BN_new();
    if (!privateKey || !BN_rand_range(privateKey, BN_value_one(), EC_GROUP_get_order(curve, NULL))) {
        fprintf(stderr, "Failed to generate private key.\n");
        return 1;
    }

    // 3. Compute public key
    EC_POINT *publicKey = EC_POINT_new(curve);
    if (!publicKey || !EC_POINT_mul(curve, publicKey, privateKey, EC_GROUP_get_generator(curve), NULL, NULL)) {
        fprintf(stderr, "Failed to generate public key.\n");
        return 1;
    }

    // Print keys (for demonstration)
    char *privateKeyHex = BN_bn2hex(privateKey);
    char *publicKeyHex = EC_POINT_point2hex(curve, publicKey, POINT_CONVERSION_UNCOMPRESSED, NULL);

    printf("Private Key: %s\n", privateKeyHex);
    printf("Public Key: %s\n", publicKeyHex);

    // Cleanup
    OPENSSL_free(privateKeyHex);
    OPENSSL_free(publicKeyHex);
    BN_free(privateKey);
    EC_POINT_free(publicKey);
    EC_GROUP_free(curve);

    return 0;
}
