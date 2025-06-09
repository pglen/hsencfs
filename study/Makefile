
#.c.o:

all:

ecc:
	gcc ecc_key.c -l crypto -l ssl -o ecc_key

ssl:
	gcc ssl.c -l crypto -l ssl -o ssl

enc:
	gcc ecc_enc.c -l crypto -l ssl -o ecc_enc

rsa_exa:  rsa_exa.c
	gcc rsa_exa.c -l crypto -l ssl -o rsa_exa

gen_rsa:  gen_rsa.c
	gcc gen_rsa.c -l crypto -l ssl -o gen_rsa

EVP_PKEY_RSA_keygen: EVP_PKEY_RSA_keygen.c
	gcc EVP_PKEY_RSA_keygen.c -l crypto -l ssl -o EVP_PKEY_RSA_keygen

test_xalloc: test_xalloc.c  ../common/xmalloc.c
	gcc -D_FILE_OFFSET_BITS=64 test_xalloc.c ../common/xmalloc.c \
                    -o test_xalloc

test_hsencfs: test_hsencfs.c
	gcc -D_FILE_OFFSET_BITS=64 -I../common -I../src test_hsencfs.c \
            ../common/hsutils.c ../common/xmalloc.c \
            -o test_hsencfs


# EOF
