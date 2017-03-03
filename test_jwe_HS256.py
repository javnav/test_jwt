#!/usr/bin/env python

import jose
import logging
import sys
from Crypto.PublicKey import RSA
from time import time

# Get an instance of a logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# key for demonstration purposes
external_key = RSA.generate(2048)
mtb_key = RSA.generate(2048)


# JWE encode - encrypt info using the public key MtB
info = {
    'company': 'ACME',
    'author': 'pepe',
    'experiment': 'ID' 
}
print "\n\t START"
print "\t    |"
print "\t< Secret information:" + str(info) + " >"
print "\t    |"
print "\t< Encrypt information (information, MtB public key) >"
print "\t    |"
try:
    pub_jwk = {'k': mtb_key.publickey().exportKey('PEM')}
    jwe = jose.encrypt(info, pub_jwk)
    # issue the compact serialized version to the clients. this is what will be
    # transported along with requests to target systems.
    secret = jose.serialize_compact(jwe)
    print "\t   OK"
    print "\t    |"
except:
    print "\tError encrypting information! " 
    e = sys.exc_info()[0]
    print "Error: %s" % e  
    exit()

# JWT sign - Sign token using the private key External
claims = {
    'from': 'mindthebyte',
    'exp': int(time()) + 3600,
    'secret': secret,
}
print "\t< claims to be signed: " + str(claims)
print "\t    |"
print "\t< Sing token signature (claims, private external key) >"
print "\t    |"
try:
    jwk = {'k': 'password'}
    jws = jose.sign(claims, jwk, alg='HS256')
    # JWS(header='eyJhbGciOiAiSFMyNTYifQ',
    # payload='eyJpc3MiOiAiaHR0cDovL3d3dy5leGFtcGxlLmNvbSIsICJzdWIiOiA0MiwgImV4cCI6IDEzOTU2NzQ0Mjd9',
    # signature='WYApAiwiKd-eDClA1fg7XFrnfHzUTgrmdRQY4M19Vr8')
    # issue the compact serialized version to the clients. this is what will be
    # transported along with requests to target systems.
    jwt = jose.serialize_compact(jws)
    # 'eyJhbGciOiAiSFMyNTYifQ.eyJpc3MiOiAiaHR0cDovL3d3dy5leGFtcGxlLmNvbSIsICJzdWIiOiA0MiwgImV4cCI6IDEzOTU2NzQ0Mjd9.WYApAiwiKd-eDClA1fg7XFrnfHzUTgrmdRQY4M19Vr8'
    print "\t   OK"
    print "\t    |"
except:
    print "\tError signing token! " 
    e = sys.exc_info()[0]
    print "Error: %s" % e  
    exit()

# Send token 
print "\t< Send Token >"
print "\t    |"
print "\t+-------+                               +-------+"
print "\t|       |                               |       |"
print "\t|   BA  +----- INTERNET (bad guys) ----->  MtB  |"
print "\t|       |                               |       |"
print "\t+-------+                               +-------+"
print "\t    |"
print "\t< Receive Token >"
print "\t    |"
# Verify Token using public key external
print "\t< Verify token signature (token, public external key) >"
print "\t    |"
try:
    signed_jws = jose.verify(jose.deserialize_compact(jwt), jwk, 'HS256') 
    print "\t   OK"
    print "\t    |"
except:
    print "\tWrong token signature! " 
    print "\tError signing token! " 
    e = sys.exc_info()[0]
    print "Error: %s" % e  
    exit()




print "\t< Decrypt information (information, MtB private key) >"
print "\t    |"
try:
    # JWT(header={u'alg': u'HS256'}, claims={u'iss': u'http://www.example.com', u'sub': 42, u'exp': 1395674427})
    header = signed_jws[0]
    claims = signed_jws[1]

    # JWE decode secret
    secret = claims['secret']

    # decrypt on the other end using the private key
    priv_jwk = {'k': mtb_key.exportKey('PEM')}
    jwe = jose.deserialize_compact(secret)
    decoded = jose.decrypt(jwe, priv_jwk)
    # JWT(header={u'alg': u'RSA-OAEP', u'enc': u'A128CBC-HS256'},
    # claims={})
    print "\t< Decoded information:" + str(decoded) + " >"
    print "\t    |"
    print "\t   END"
except:
    print "\tError encrypting information! " 
    e = sys.exc_info()[0]
    print "Error: %s" % e  
    exit()
