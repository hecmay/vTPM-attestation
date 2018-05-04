#! /usr/bin/env python
# coding:utf-8 #

''' This part provides the functionality 
    to verify the cerdentials of UEFI clients
    based on the history data and return the response
'''
import re
import ssl
import time
import datetime
import base64
import binascii
from os.path import exists, join
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

def random_number():
    return random.getrandbits(24)

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

def rsa_sign(msg, private_key):
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
    Retrieve the public key from a X509 Certificate in PEM format. 
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

'''
    Retrive public key from cert in PEM format
'''
def prvkey_from_pem(cert):
    with open(cert,"r") as f:
         key = f.read()
         prvkey = RSA.importKey(key) 
    return prvkey 

def extarct_components(cert):
    # extract (n, e) components from der cert
    from asn1crypto.x509 import Certificate
    with open(cert, "rb") as f:
        cert = Certificate.load(f.read())
    
    n = cert.public_key.native["public_key"]["modulus"]
    e = cert.public_key.native["public_key"]["public_exponent"]
    
    print("{:#x}".format(n))    # prints the modulus (hexadecimal)
    print("{:#x}".format(e))    # same, for the public exponent


''' Attempt to adopt the binarized bitmap 
    to visualize the dataset in the sqlite
'''
def record_to_bitmap():
    pass


''' Wrapper of OpenSSL crypto
    Create X509 Cert in DER format and private Key
'''
def create_x509_cert(cert_dir):
    if not exists(join(cert_dir, "prvkey.pem")):
      from cryptography import x509
      from cryptography.x509.oid import NameOID
      from cryptography.hazmat.primitives import hashes
      from cryptography.hazmat.backends import default_backend
      from cryptography.hazmat.primitives import serialization
      from cryptography.hazmat.primitives.asymmetric import rsa
      # Generate private key
      key = rsa.generate_private_key(
          public_exponent=65537,
          key_size=2048,
          backend=default_backend()
      )
      # Write our key to disk for safe keeping
      with open("prvkey.pem", "wb") as f:
          f.write(key.private_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PrivateFormat.TraditionalOpenSSL,
              encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
          ))
      
      # Various details about who we are. For a self-signed certificate the
      # subject and issuer are always the same.
      subject = issuer = x509.Name([
          x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
          x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"BJ"),
          x509.NameAttribute(NameOID.LOCALITY_NAME, u"BJ"),
          x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Siemens"),
          x509.NameAttribute(NameOID.COMMON_NAME, u"Siemens"),
      ])
      cert = x509.CertificateBuilder().subject_name(
          subject
      ).issuer_name(
          issuer
      ).public_key(
          key.public_key()
      ).serial_number(
          x509.random_serial_number()
      ).not_valid_before(
          datetime.datetime.utcnow()
      ).not_valid_after(
          datetime.datetime.utcnow() + datetime.timedelta(days=365)
      ).add_extension(
          x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
          critical=False,
      ).sign(key, hashes.SHA256(), default_backend())
      # Write our certificate out to disk.
      with open("certificate.pem", "wb") as f:
          f.write(cert.public_bytes(serialization.Encoding.PEM))
      with open("certificate.der", "wb") as f:
          f.write(cert.public_bytes(serialization.Encoding.DER))


def create_self_signed_cert(cert_dir):
    """
    cert/key pair creation implementation using OpenSSL crypto lib.
    If datacard.crt and  don't exist in cert_dir, create a new
    self-signed cert and keypair and write them into that directory.
    """
    from OpenSSL import crypto
    if not exists(join(cert_dir, "crypt_cert.der")) \
	    or not exists(join(cert_dir, "crypt_key.pem")) \
            or not exists(join(cert_dir, "crypt_pub.pem")):

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "CN"
        cert.get_subject().ST = "BJ"
        cert.get_subject().L = "BJ"
        cert.get_subject().O = "Siemens"
        cert.get_subject().OU = "Corporation Technology"
        cert.get_subject().CN = "Siemens"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        open(join(cert_dir, "crypt_cert.der"), "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))
        open(join(cert_dir, "crypt_cert.pem"), "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open(join(cert_dir, "crypt_key.pem"), "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        open(join(cert_dir, "crypt_pub.pem"), "wt").write(
            crypto.dump_publickey(crypto.FILETYPE_PEM, k))


if __name__ == '__main__':
    create_x509_cert(".")
    create_self_signed_cert(".")

    plain = "123456woshixxx"
    pubkey = prvkey_from_pem("crypt_pub.pem")
    #ppk = pubkey_from_x509("crypt_cert.pem")
    encode = rsa_encryption(plain, pubkey)
    print "[Test] X509 pem encode: ", encode, '\n' 

    prvkey = prvkey_from_pem("crypt_key.pem")
    decode = rsa_decryption(encode, prvkey)
    print "[Test] X509 pem decode", decode, '\n'

    digest = SHA256.new()
    digest.update(str(-729373007))
    print "Raw Session key: ", str(digest.hexdigest())

    hex_str = get_session_key([0,0,-729373007])
    aes_encrypt = AES_ENCRYPT(hex_str) 
    print "The session key[d]: %s", len(hex_str), hex_str

    text = "Pre Master: -1875847051========="
    e = aes_encrypt.encrypt(text)
    d = aes_encrypt.decrypt(e)
    print text
    print e
    print d
  
    raw = "1FEE1726FC38FBE5E533C441B1D28C7B63552AEA1DBAE847D149A0043A63E04A"
    d1 = aes_encrypt.decrypt(raw)
    print "Check: ", d1

    # Test of Extracting key from DER Cert 
    print "\n\n[Test Der]"
    key = prvkey_from_pem("cert.pem")
    org = rsa_encryption("Test", key) 
    print b2a_hex(org)
   
    prvkey = prvkey_from_pem("crypt_key.pem")
    rsa_text ="1D17BB26D3510EABF2B06C9020895B587DA4EF1ED8F966FF8BBB7E3EB6F85F593D65E97DAA0FE80049F5B205ED2E881C27569BFA525E78EBE825ECDC338BDBA0EF0CBED3F8A38C5C001FA148E453EDBECF9C44CB350815DDAFDA8B252B53A1304F55FD0923EE8B9BF0F464C0B850598D887BD04D3A90F641FBCF45A7E7E7678B"
    encode = base64.b64encode(a2b_hex(rsa_text)) 
    print "[Base64] ", encode
    decode = rsa_decryption(encode, prvkey)
    print "[Test] X509 pem decode", decode, '\n'
