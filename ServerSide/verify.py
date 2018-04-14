#! /usr/bin/env python
# coding:utf-8 #

''' This part provides the functionality 
    to verify the cerdentials of UEFI clients
    based on the history data and return the response
'''
import re
import ssl
import time
import base64
from binascii import a2b_base64
from Crypto.Random import random
from Crypto import Random
from Crypto.Util.asn1 import DerSequence
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode

def verify_record():
    print "[INFO] Start Credential Verification...\n"
    
def random_number():
    return random.getrandbits(32)

def create_keys(keysize = 1024, save = False):
    random_generator = Random.new().read
    rsa = RSA.generate(keysize, random_generator)

    if save == True:
        private_pem = rsa.exportKey()
        with open('private.pem', 'w') as f:
            f.write(private_pem)
        public_pem = rsa.publickey().exportKey()

        with open('public.pem', 'w') as f:
            f.write(public_pem)

    return rsa, rsa.publickey()

def load_key():
    with open('public.pem',"r") as f:
         key = f.read()
         pubkey = RSA.importKey(key) 
    with open('public.pem',"r") as f:
         key = f.read()
         prvkey = RSA.importKey(key) 
    return prvkey, pubkey

def rsa_encryption(msg, public_key):
    cipher = Cipher_pkcs1_v1_5.new(public_key)
    cipher_text = base64.b64encode(cipher.encrypt(msg))
    return cipher_text

def rsa_decryption(msg, private_key):
    random_generator = Random.new().read
    cipher = Cipher_pkcs1_v1_5.new(private_key)
    text = cipher.decrypt(base64.b64decode(msg),random_generator)
    print text
    return text

def rsa_sign(msg, pricate_key):
    with open('master-private.pem') as f:
        key = f.read()
        rsakey = RSA.importKey(key)
        signer = Signature_pkcs1_v1_5.new(rsakey)
        digest = SHA.new()
        digest.update(message)
        sign = signer.sign(digest)
        signature = base64.b64encode(sign)
        return signature

def get_session_key(random_list):
     assert len(random_list) == 3, "Not Enough Item for Session Key"
     
'''
    Retrieve the public key from a X509 Certificate. 
    Since 
'''
def key_from_x509(cert):
    pem = open(cert).read()
    lines = pem.replace(" ",'').split()
    der = a2b_base64(''.join(lines[1:-1]))
    
    cert = DerSequence()
    cert.decode(der)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]
    rsa_key = RSA.importKey(subjectPublicKeyInfo)
    return rsa_key

''' Attempt to adopt the binarized bitmap 
    to visualize the dataset in the sqlite'''

pk, pubkey = create_keys()
plain = "123456woshixxx"
encode = rsa_encryption(plain, pubkey)
print encode
print pk
rsa_decryption(encode, pk)
ppk = key_from_x509("mycert.pem")

encode = rsa_encryption(plain, ppk)
print encode
