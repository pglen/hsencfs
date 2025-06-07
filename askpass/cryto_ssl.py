#!/usr/bin/env python

import os, sys

import OpenSSL

import M2Crypto
from M2Crypto import RSA
from M2Crypto import BIO

key = \
b'-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApFCQ+JBH3TInlh1PQ3vM\n\
LPqJMQ6nXfJeRdn4kZ3tdfd0luPGrOHZELZjhpxWZuVJa6vyC1xI63Qkm7r4b0EJ\n\
eM/oSbr4DA7T5gT1JYoUKIi7bNgOQ58A/eYpi6/JHtofPnuXeDiZCvGJTZQkkRVO\n\
/uPHOI+itCK0z0qvyCLgQ2BKb7y1b/luAx2Y81myP83sfCvzs6q1w/lgZ9XfsqQq\n\
wWrQZYTX1hD1zRWFfq28vYvU9CGedX/Vguavo56hf0Mms+3CuzC3DunwaGCcrX6c\n\
FoDsvLRChT6m4pA6iZwJP8gDhP6Vggojyl21C1uG0mzdm/adyJsJeik/ub8HlTNW\n\
twIDAQAB\n\
-----END PUBLIC KEY-----\n\
'
#print(key)
print("rsa", dir(RSA))
print("rsa.rsa_pub", dir(RSA.RSA_pub))
print("m2 version", M2Crypto.__version__)

#keyx = OpenSSL.crypto.load_publickey(OpenSSL.crypto.FILETYPE_PEM, key)

bio = BIO.BIO()
print("bio", bio);
bio.write(key)

#keyx = RSA.load_pub_key_bio(bio)
keyx = RSA.RSA_pub(key)
print(keyx)

sys.exit()
