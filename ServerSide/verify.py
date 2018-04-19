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
from binascii import a2b_base64, b2a_hex, a2b_hex
from Crypto.Random import random
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.asn1 import DerSequence
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode

class AES_ENCRYPT(object):
    def __init__(self, session_key):
        self.key = session_key
        self.mode = AES.MODE_CBC
        self.IV = 16 * '\x00'
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.IV)
        length = 16
        count = len(text)
        add = length - (count % length)
        text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        return b2a_hex(self.ciphertext)
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.IV)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')

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

# return a 16-bytes key for AES-128 encryption
def get_session_key(random_list):
    assert len(random_list) == 3, "Not Enough Item for Session Key"
    digest = SHA256.new()
    digest.update(str(sum(random_list)))
    return a2b_hex(str(digest.hexdigest()[0:32]))
     
'''
    Retrieve the public key from a X509 Certificate. 
    X509 is an Certificate Format defined by ANSI 
'''
def pubkey_from_x509(cert):
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


if __name__ == '__main__':
    plain = "123456woshixxx"
    ppk = pubkey_from_x509("mycert.pem")
    rsa_encryption(plain, ppk)
    
    encode = rsa_encryption(plain, ppk)
    print encode, '\n' 

    digest = SHA256.new()
    digest.update(str(368137416))
    print "Raw Session key: ", str(digest.hexdigest())

    hex_str = get_session_key([0,0,368137416])
    aes_encrypt = AES_ENCRYPT(get_session_key([0,0,368137416]))  
    print "The session key[d]: %s", len(hex_str), hex_str
    # print "Convert Str to Hex", hex(int(get_session_key([0,0,368137416]), 16))
    # print "Convert HEx Str to binary: ", bin(int(hex_str, 16))[2:]
    # print "Convert HEx Str to binary: ", a2b_hex(hex_str)
    # print "The orginal hex_str len: ", len(hex_str), "After: ", len(a2b_hex(hex_str))

    text = "Pre Master: -647657897=========="
    e = aes_encrypt.encrypt(text)
    d = aes_encrypt.decrypt(e)
    print text
    print e
    print d

    
