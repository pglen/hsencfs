
#.c.o:

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


# EOF
