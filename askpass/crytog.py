#!/usr/bin/env python

import os, sys

import cryptography
print("cryptography version:", cryptography.__version__)
print(dir(cryptography))

import cryptography_vectors
print("cryptography_vectors", cryptography_vectors.__version__)

key = \
'-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApFCQ+JBH3TInlh1PQ3vM\n\
LPqJMQ6nXfJeRdn4kZ3tdfd0luPGrOHZELZjhpxWZuVJa6vyC1xI63Qkm7r4b0EJ\n\
eM/oSbr4DA7T5gT1JYoUKIi7bNgOQ58A/eYpi6/JHtofPnuXeDiZCvGJTZQkkRVO\n\
/uPHOI+itCK0z0qvyCLgQ2BKb7y1b/luAx2Y81myP83sfCvzs6q1w/lgZ9XfsqQq\n\
wWrQZYTX1hD1zRWFfq28vYvU9CGedX/Vguavo56hf0Mms+3CuzC3DunwaGCcrX6c\n\
FoDsvLRChT6m4pA6iZwJP8gDhP6Vggojyl21C1uG0mzdm/adyJsJeik/ub8HlTNW\n\
twIDAQAB\n\
-----END PUBLIC KEY-----\n\
'
from cryptography.hazmat.primitives import serialization

keyx = serialization.load_pem_private_key(key, password=None)

print(keyx)

sys.exit()
