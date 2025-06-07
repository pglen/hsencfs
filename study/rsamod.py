#!/usr/bin/env python

import os, sys
#import getopt, signal, select, string, time
#import struct, stat, base64, random

import ctypes

#clib = cdll.LoadLibrary("libc.so.6")
#print("C_LIB")
#print(dir(clib))
#print(clib.rand())
#sys.exit()

try:
    ssl_lib = ctypes.cdll.LoadLibrary("libssl3.so")
    #ssl_lib = ctypes.CDLL("libssl3.so")

except:
    print("Must have libss33", sys.exc_info());

try:
    crypto_lib = ctypes.cdll.LoadLibrary("libcrypto.so")
except:
    print("Must have libcrypto");

#print("CRYPT_LIB")
#print(dir(crypt_lib))

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

BIO_new_mem_buf = crypto_lib.BIO_new_mem_buf

#BIO_new_mem_buf.restype = ctypes.c_char_p
#print("func", BIO_new_mem_buf)

ptr = BIO_new_mem_buf(key, -1)
print("ptr", ptr)

PEM_read_bio_RSA_PUBKEY = crypto_lib.PEM_read_bio_RSA_PUBKEY

i = ctypes.c_int(0)
ptr2=ctypes.pointer(i)

ret = PEM_read_bio_RSA_PUBKEY(ptr, ptr2, None, None)

print("ret", ret)

sys.exit()


class rsamod_c:
    pass

import rsamod as rsamod_c

# Mirror 'c'  function versions

def version():
    return rsamod_c.version()

def builddate():
    return rsamod_c.builddate()

def encrypt(buff, passwd):
    rrr = rsamod_c.encrypt(buff, passwd)
    return rrr

def decrypt(buff, passwd):
    rrr = rsamod_c.decrypt(buff, passwd)
    return rrr

def tohex(buff):
    rrr = rsamod_c.tohex(buff);   #//buff.encode("cp437"))
    return rrr

def fromhex(buff):
    rrr = rsamod_c.fromhex(buff)
    return rrr

def destroy(buff, fill = 0):
    rsamod_c.destroy(buff, fill)
    pass

#OPEN = rsamod_c.OPEN
#author = rsamod_c.author
#dict = rsamod_c.__dict__

# EOF
