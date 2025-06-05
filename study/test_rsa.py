#!/usr/bin/python

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

pub = \
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

pri = \
b'-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkUJD4kEfdMieW\n\
HU9De8ws+okxDqdd8l5F2fiRne1193SW48as4dkQtmOGnFZm5Ulrq/ILXEjrdCSb\n\
uvhvQQl4z+hJuvgMDtPmBPUlihQoiLts2A5DnwD95imLr8ke2h8+e5d4OJkK8YlN\n\
lCSRFU7+48c4j6K0IrTPSq/IIuBDYEpvvLVv+W4DHZjzWbI/zex8K/OzqrXD+WBn\n\
1d+ypCrBatBlhNfWEPXNFYV+rby9i9T0IZ51f9WC5q+jnqF/Qyaz7cK7MLcO6fBo\n\
YJytfpwWgOy8tEKFPqbikDqJnAk/yAOE/pWCCiPKXbULW4bSbN2b9p3Imwl6KT+5\n\
vweVM1a3AgMBAAECggEAB5wP+RfDFD99FArCDHrtWKa23gKmBdSyWmOYi00RxCHt\n\
9taQPjQGN8VsNFdrxiXxPmv/CiXZRK1v/2K4Na+aSJhZICA2DTNOMe77cXEeTOBE\n\
M2uJtMaZptu9adHKxSobdbfTxHmoI/8an9dwBOR3o5gZHLzElex58vp4/viw6fED\n\
ki0k6Vx7BpAeLYEJ7sAGzBgb8baCKWYM6pcdXyug1q7Cf6Tt6OtDPc+1p3lSF0aw\n\
gZORs795onDHyb9NAYxxFegvQJ/Br7Mg+ShZn3irLjyi2BNNCx6jjTa9k208kqhO\n\
JgkOxoBuDi4FknoQ6dWEuSxA6YTZ48ZiXiJm+E0IIQKBgQDOlwfJLjvjGHwMxegm\n\
HRKaxt81HqoGPjXIxt2upAcPOK6+iiEDLEr+9PJ8hTT/uQVQKjyPFqnJitE30tHv\n\
5rLwIMbVwIMbc+0ns4xE2Om1F3Bh6QCszMsWjjv4nOvKxanvsaTftyR/EzzVMEH4\n\
vf4Zo7xacGw0kJQe6OD/ijagIQKBgQDLnSGr+/yM8hM+QaJ7bXUsMpQ94mLZpyoJ\n\
y/d6Vqu/1OqhbmUkV1osOrd6tWxKsdnHUvORxvA/Ch/Sx+1hxlNhLrtNknNQqtFo\n\
Kh6lQjdF+nuympHg3xm4aAqkCgXqMKl3yiOmzJeKzaR1gOV/RulOwzNuqKCUo2IW\n\
JyXaIgN71wKBgD/SHI+j/tA7QidYBE2x8YtrII1yeagQE+GAvf8zoRKsuh8W4Pfv\n\
+QMmfLrHFAZkDCYlxiuWHsGqZtPOBxkLtf/EwGhMXrRebcc0CoNCV4CgSxGUP6ci\n\
ZSMEsbYuFBHCWqs3v+100IuJT+O0Us0bNKKLGKb/0A21FG0wGEIZWqLBAoGBAI1s\n\
hoa+b5w2R8dmL0UrsccRGoYhSCeFRF2pnisLKCAF8zJNS1MCmU8/OVGx0ZXQEkOw\n\
Ch2m4BfpIFF3LBpNdnx5yP8ISbAt9WU0XDTM2Tdx05kqY0idrW+4VCu8Cn+vbQYX\n\
EMw6LsfqLeCvtrfAuSxLyN2DooWbNfXNGy13kpPhAoGAYFnrb0kkltGYhAtOwm7G\n\
i9N1kQsrP1kYYDd6WdwcjnTRD66G3bFZWECRMZusUsGyCPXhgJSEtDsgTWKsU4Ph\n\
gWevkN5MdWEYwgi7pAx1wimdrO7VRL7sUUkdjKrwRfgFgQPq4voGuuBx+1F3O5Hm\n\
tnhMZauL5DTmZyS+2OfFl6s=\n\
-----END PRIVATE KEY-----\n\
'

pkey = RSA.import_key(pub)
vkey = RSA.import_key(pri)

text = "1234123412341234123412341234123412341234123412341234"
print("org:", text.encode())

cipher_rsa = PKCS1_OAEP.new(pkey)
enc_text = cipher_rsa.encrypt(text.encode())

cipher_rsa2 = PKCS1_OAEP.new(vkey)

dec_text = cipher_rsa2.decrypt(enc_text)

print("unc:", dec_text)

#print("de_text", b"'" + dec_text + b"'")
#sss = base64.b64encode(text.encode())

print("len: enc_text", len(enc_text))

