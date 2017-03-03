# Workflow

```

	 START
	    |
	< Secret information:{'company': 'ACME', 'experiment': 'ID', 'author': 'foo'} >
	    |
	< Encrypt information (information, MtB public key) >
	    |
	   OK
	    |
	< claims to be signed: {'timestamp': 1488556002, 'secret': 'eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkExMjhDQkMtSFMyNTYiLCAiX192IjogMn0.Nw3o_JXjRN8UoiO77eXDZjYgjsecdru4xn82GdBA9m9mVo7VM9vlPCrvZveBGnPi7RZ229FSVf8BLIXeAFfyDFNToJm7sR0XqjEQX61ESlLzlxYY0zgK9sw-PL5VqTzcl3ESnaZYgwB_F_H2EDT1U0RpjSgBQwRER-ozCouecOkbXT7NKC7cDLOkVaVG7-RnS4JDCJ0i0eX3slSGkDWT1ldbqFLUcOqPiEq5510iBoBG4SmnQgJRT67WwWN5ZWDfG21yYCdk2Mkm3U8ZcUTp1IzgLKN_U7LTI0OWyAGVgLFxg2nCuWMkDVF2FCbsFCgWOHM2uXMUJZTbCG2U8_sU1Q.SAHpqNJ8caAKOkSgSxMp1A.pUlMkgwDCO3cq2wHWRtZ_mwiV2jJ6MQnRJ-4FrW1ngMLQPOblrbelc8uFOe6nXutAhEXSduVkeWxVgG3CVFb2kTd2StThP0t3h7EaUrrnoU.Rm4-iy5sJ7nvFJ9c0Cswbg', 'from': 'mindthebyte'}
	    |
	< Sign token (claims, private external key) >
	    |
	   OK
	    |
	< Send Token >
	    |
	+-------+                               +-------+
	|       |                               |       |
	|   BA  +----- INTERNET (bad guys) ----->  MtB  |
	|       |                               |       |
	+-------+                               +-------+
	    |
	< Receive Token >
	    |
	< Verify token signature (token, public external key) >
	    |
	   OK. Secret received from mindthebyte with timestamp 1488556002
	    |
	< Decrypt information (information, MtB private key) >
	    |
	< Decoded information:JWT(header={u'alg': u'RSA-OAEP', u'enc': u'A128CBC-HS256', u'__v': 2}, claims={u'company': u'ACME', u'experiment': u'ID', u'author': u'foo'}) >
	    |
	   END
```




## JWS - JSON Web Signature
JSON Web Signatures (JWS) are used to digitally sign a JSON encoded object and represent it as a compact URL-safe string.
```
from jose import jws
from Crypto.PublicKey import RSA
signed = jws.sign({'a': 'b'}, 'secret', algorithm='RS512')
signed
```

* Verifying token signatures
```
jws.verify(signed, 'secret', algorithm='RS512')
{'a': 'b'}
```

## JWT - JSON Web Token
JSON Web Tokens (JWT) are a JWS with a set of reserved claims to be used in a standardized manner.
```
from jose import jwt
from Crypto.PublicKey import RSA
f = open('test_rsa','r')
r=RSA.importKey(f.read(),passphrase='foo')
token = jwt.encode({'a': 'b'}, r, algorithm='RS512')
token
```

Warning: JWT is signed but contents are public
```
jwt.get_unverified_header(token)
{u'alg': u'RS512', u'typ': u'JWT'}
jwt.get_unverified_headers(token)
{u'alg': u'RS512', u'typ': u'JWT'}
jwt.get_unverified_claims(token)
{u'a': u'b'}
```

```
from jose import jwt as jwt_client
jwt_client.get_unverified_header(token)
{u'alg': u'RS512', u'typ': u'JWT'}

jwt_client.get_unverified_headers(token)
{u'alg': u'RS512', u'typ': u'JWT'}

jwt_client.get_unverified_claims(token)
{u'a': u'b'}

f = open('test_rsa.pub','r')
r=RSA.importKey(f.read(),passphrase='foo')
jwt.decode(token, r.publickey().exportKey(), algorithms='RS512')
{u'a': u'b'}


r.publickey().exportKey()
'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChJT2loVT4kaHJ/rLREAjITkf2\nx5AnJpynPVOxN78fQp1Ma4DV0MiU5sbK6H9rtWf61OFPiIhaBTJYTJVvdCL5ccDk\nN7VR7R7P6eF9ZZG1t7byWad1tu4e+nPWdad9Qmn4l48XV1DGe2tjulyGkJgiRHmG\nrwrWuyN2AfF94hBwGQIDAQAB\n-----END PUBLIC KEY-----'

bad_r='-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChJT2loVT4kaHJ/rLREAjITkf2\nx5AnJpynPVOxN78fQp1Ma4DV0MiU5sbK6H9rtWf61OFPiIhaBTJYTJVvdCL5ccDk\nN7VR7R7P6eF9ZZG1t7byWad1tu4e+nPWdad9Qmn4l48XV1DGe2tjulyGkJgiRHmG\nrwrWuyN2AfF94hBwGQIDAQCB\n-----END PUBLIC KEY-----'
jwt.decode(token, bar_r, algorithms='RS512')
>>> jwt.decode(token, bad_r, algorithms='RS512')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/jnavarro/workspace/tests/JWT/python_jose/.venv/local/lib/python2.7/site-packages/jose/jwt.py", line 134, in decode
    raise JWTError(e)
jose.exceptions.JWTError: Signature verification failed.

## pycryptodome Examples
https://pycryptodome.readthedocs.io/en/latest/src/examples.html#generate-an-rsa-key

### Generate an RSA key
The following code generates a new RSA key pair (secret) and saves it into a file, protected by a password. We use the scrypt key derivation function to thwart dictionary attacks. At the end, the code prints our the RSA public key in ASCII/PEM format:

from Crypto.PublicKey import RSA

secret_code = "Unguessable"
key = RSA.generate(2048)
encrypted_key = key.exportKey(passphrase=secret_code, pkcs=8,
                              protection="scryptAndAES128-CBC")

file_out = open("rsa_key.bin", "wb")
file_out.write(encrypted_key)

print key.publickey().exportKey()

The following code reads the private RSA key back in, and then prints again the public key:

from Crypto.PublicKey import RSA

secret_code = "Unguessable"
encoded_key = open("rsa_key.bin", "rb").read()
key = RSA.import_key(encoded_key, passphrase=secret_code)

print key.publickey().exportKey()


### Read from file
```
f = open('test_rsa','r')
r=RSA.importKey(f.read(),passphrase='foo')
print r.publickey().exportKey()
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChJT2loVT4kaHJ/rLREAjITkf2
x5AnJpynPVOxN78fQp1Ma4DV0MiU5sbK6H9rtWf61OFPiIhaBTJYTJVvdCL5ccDk
N7VR7R7P6eF9ZZG1t7byWad1tu4e+nPWdad9Qmn4l48XV1DGe2tjulyGkJgiRHmG
rwrWuyN2AfF94hBwGQIDAQAB
-----END PUBLIC KEY-----

print r.exportKey()
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQChJT2loVT4kaHJ/rLREAjITkf2x5AnJpynPVOxN78fQp1Ma4DV
0MiU5sbK6H9rtWf61OFPiIhaBTJYTJVvdCL5ccDkN7VR7R7P6eF9ZZG1t7byWad1
tu4e+nPWdad9Qmn4l48XV1DGe2tjulyGkJgiRHmGrwrWuyN2AfF94hBwGQIDAQAB
AoGAXhXYQHRJoDenNsC2tsmd1xWdfsBVsgYhQKPV0Yqy1BWYsZ2ywyP7eLSlLKNC
giiQZSsVwdH9ilGua0+LkF9Ga2A5QGM/qKC89XXdf8DKN3sTHAjFx6LY+h4+M2ha
AHKJYQJwnHe/9C7/SRYsrwaGSia2Lhh9v2SmlliOhHhQhOECQQDV4WyVSirzrdKC
6Vz5S+Jm20P8u5+AZ0zgeZgwa3qq6KCrFceizuNql4YHCUwSPGs6SW77Ih65EzdP
K1ugmii7AkEAwOE6v7H9mTktcmdBkKe3jjtHaZgSGdWSvE9wzkU18YS+xOjcQPmy
y4u3cthOHXI+XaC54tKrChr7o878J7zXOwJBAJqMy0bRkloFaBG7CbkHMbF7jhRJ
i8dgXffzRZrvf3OSp88Y7Opjr4etuGbLPBINYLp8p9qG3EaGcTgfL5XM79MCQASM
Cr+EKa9YCrs8te38FjazLQ7PN/YF8+yejtE+DnSAJaMsviyF9nIX/B4n/Udybwf0
Bw3S25dkZXRKJ+Wj7QsCQFQ+VBQAPi3R0OZZNuMTUnJi07ozBY69pkpVV7PWjZys
RZue0Pca4a+z7nzb4rFB/QQEaNcmAbuPsh1kwUoL5t0=
-----END RSA PRIVATE KEY-----
```




### STORE API Keys in an external file

Store the API Key in an external file and load it at runtime. Just be sure to never commit the external file or publish it. Obfuscating the key once loaded doesn't really prevent them from stealing it (especially if they have the source to unwind your obfuscation as jonrsharpe pointed out).

Heres a crude example, I'm sure you could refine it to suit your needs:

secret_keys file:
```

{
    "TWITTER_SECRET" : "somebase64encodedkey"
}
```

python:

```

import json

secrets_filename = 'secret_keys'
api_keys = {}
with open(secrets_filename, 'r') as f:
    api_keys = json.loads(f.read())

print api_keys['TWITTER_SECRET'] # somebase64encodedkey
```



### Using pycrypto, how to import a RSA public key and use it to encrypt a string?

I too had trouble with this. I got it working like this:
```
key = RSA.generate(2048)

binPrivKey = key.exportKey('DER')
binPubKey =  key.publickey().exportKey('DER')

privKeyObj = RSA.importKey(binPrivKey)
pubKeyObj =  RSA.importKey(binPubKey)

msg = "attack at dawn"
emsg = pubKeyObj.encrypt(msg, 'x')[0]
dmsg = privKeyObj.decrypt(emsg)

assert(msg == dmsg)
```

If you're writing to files, you may find it easier to deal with hex strings instead of binary strings. I'm using these helper functions a lot
```

def bin2hex(binStr):
    return binascii.hexlify(binStr)
```
```

def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)
```

### Links
https://python-jose.readthedocs.io/en/latest/jwk/index.html#verifying-token-signatures
http://learncodingfast.com/2015/04/14/python-tutorial-how-to-write-a-simple-encryptiondecryption-program/
http://stackoverflow.com/questions/37289672/which-python-jose-library-supports-nested-jwt-signedencrypted
http://stackoverflow.com/questions/21327491/using-pycrypto-how-to-import-a-rsa-public-key-and-use-it-to-encrypt-a-string
http://stackoverflow.com/questions/30056762/rsa-encryption-and-decryption-in-python



