#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import os
import hmac
import time
import math
import hashlib
import logging

from bluepass.ext import openssl

CryptoError = openssl.Error

# Some useful commonly used DH parameters.
dhparams = \
{
    'skip2048': """
    MIIBCAKCAQEA9kJXtwh/CBdyorrWqULzBej5UxE5T7bxbrlLOCDaAadWoxTpj0BV
    89AHxstDqZSt90xkhkn4DIO9ZekX1KHTUPj1WV/cdlJPPT2N286Z4VeSWc39uK50
    T8X8dryDxUcwYc58yWb/Ffm7/ZFexwGq01uejaClcjrUGvC/RgBYK+X0iP1YTknb
    zSC0neSRBzZrM2w4DUUdD3yIsxx8Wy2O9vPJI8BD8KVbGI2Ou1WMuF040zT9fBdX
    Q6MdGGzeMyEstSr/POGxKUAYEY18hKcKctaGxAMZyAcpesqVDNmWn6vQClCbAkbT
    CD1mpF1Bn5x8vYlLIhkmuquiXsNV6TILOwIBAg==
    """.decode('base64'),
    'ietf768': """
    MGYCYQD//////////8kP2qIhaMI0xMZii4DcHNEpAk4IimfMdAILvqY7E5siUUoIeY40BN3vlRmz
    zTpDGzArCm3yXxQ3T+E1bW1RwkXkhbV2Yl5+xvRMQummOjYg//////////8CAQI=
    """.decode('base64'),
    'ietf1024': """
    MIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+V
    GbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8k
    EXxLH+ZJKGZR7OZTgf//////////AgEC
    """.decode('base64')
}


class CryptoProvider(object):
    """Crypto provider.

    This class exposes the cryptographic primitives that are required by
    Bluepass. Currently the only available engine is OpenSSL, but at some
    point this could use a native platform crypto provider.
    """

    _pbkdf2_speed = None

    def __init__(self, engine=None):
        """Create a new crypto provider."""
        self.engine = engine or openssl

    def rsa_genkey(self, bits):
        """Generate an RSA key pair of `bits' bits. The result is a 2-tuple
        containing the private and public keys. The keys themselves as ASN.1
        encoded bitstrings.
        """
        return self.engine.rsa_genkey(bits)

    def rsa_checkkey(self, privkey):
        """Check that `privkey' is a valid RSA private key."""
        return self.engine.rsa_checkkey(privkey)

    def rsa_size(self, pubkey):
        """Return the size in bits of an RSA public key."""
        return self.engine.rsa_size(pubkey)

    def rsa_encrypt(self, s, pubkey, padding='oaep'):
        """RSA Encrypt a string `s' with public key `pubkey'. This uses direct
        encryption with OAEP padding.
        """
        return self.engine.rsa_encrypt(s, pubkey, padding)

    def rsa_decrypt(self, s, privkey, padding='oaep'):
        """RSA Decrypt a string `s' using the private key `privkey'."""
        return self.engine.rsa_decrypt(s, privkey, padding)

    def rsa_sign(self, s, privkey, padding='pss-sha256'):
        """Create a detached RSA signature of `s' using private key
        `privkey'."""
        return self.engine.rsa_sign(s, privkey, padding)

    def rsa_verify(self, s, sig, pubkey, padding='pss-sha256'):
        """Verify a detached RSA signature `sig' over `s' using the public key
        `pubkey'."""
        return self.engine.rsa_verify(s, sig, pubkey, padding)

    def dh_genparams(self, bits, generator):
        """Generate Diffie-Hellman parameters. The prime will be `bits'
        bits in size and `generator' will be the generator."""
        return self.engine.dh_genparams(bits)

    def dh_checkparams(self, params):
        """Check Diffie-Hellman parameters."""
        return self.engine.dh_checkparams(params)

    def dh_size(self, params):
        """Return the size in bits of the DH parameters `params'."""
        return self.engine.dh_size(params)

    def dh_genkey(self, params):
        """Generate a Diffie-Hellman key pair. The return value is a tuple
        (privkey, pubkey)."""
        return self.engine.dh_genkey(params)

    def dh_checkkey(self, params, pubkey):
        """Check a Diffie-Hellman public key."""
        return self.engine.dh_checkkey(params, pubkey)

    def dh_compute(self, params, privkey, pubkey):
        """Perform a Diffie-Hellman key exchange. The `privkey' parameter is
        our private key, `pubkey' is our peer's public key."""
        return self.engine.dh_compute(params, privkey, pubkey)

    def aes_encrypt(self, s, key, iv, mode='cbc-pkcs7'):
        """AES encrypt a string `s' with key `key'."""
        return self.engine.aes_encrypt(s, key, iv, mode)

    def aes_decrypt(self, s, key, iv, mode='cbc-pkcs7'):
        """AES decrypt a string `s' with key `key'."""
        return self.engine.aes_decrypt(s, key, iv, mode)

    def pbkdf2(self, password, salt, count, length, prf='hmac-sha256'):
        """PBKDF2 key derivation function from PKCS#5."""
        return self.engine.pbkdf2(password, salt, count, length, prf)

    def _measure_pbkdf2_speed(self):
        """Measure the speed of PBKDF2 on this system."""
        salt = password = '0123456789abcdef'
        length = 1; count = 1000
        logger = logging.getLogger(__name__)
        logger.debug('starting PBKDF2 speed measurement')
        while True:
            start = time.time()
            self.pbkdf2(password, salt, count, length)
            end = time.time()
            if end - start > 0.5:
                break
            count = int(count * math.e)
        speed = int(count / (end - start))
        logger.debug('PBKDF2 speed is %d iterations / second', speed)
        # Store the speed in the class so that it can be re-used by
        # other instances.
        type(self)._pbkdf2_speed = speed

    def pbkdf2_speed(self, prf='hmac-sha256'):
        """Return the speed in rounds/second for generating a key
        with PBKDF2 of up to the hash length size of `prf`."""
        if self._pbkdf2_speed is None:
            self._measure_pbkdf2_speed()
        return self._pbkdf2_speed

    def random(self, count, alphabet=None, separator=None):
        """Create a random string.
        
        The random string will be the concatenation of `count` elements
        randomly chosen from `alphabet`. The alphabet parameter can be a
        string, unicode string, a sequence of strings, or a sequence of unicode
        strings. If no alphabet is provided, a default alphabet is used
        containing all possible single byte values (0 through to 255).

        The type of the return value is the same as the elements in the
        alphabet (string or unicode).
        """
        return self.engine.random(count, alphabet, separator)

    def randint(self, bits):
        """Return a random integer with `bits' bits."""
        nbytes = (bits + 7) / 8
        mask = (1<<bits)-1
        return int(self.random(nbytes).encode('hex'), 16) & mask

    def randuuid(self):
        """Return a type-4 random UUID."""
        return '%08x-%04x-4%03x-%04x-%012x' % \
               (self.randint(32), self.randint(16), self.randint(12),
                0x8000 + self.randint(14), self.randint(48))

    def _get_hash(self, name):
        """INTERNAL: return a hash contructor from its name."""
        if not hasattr(hashlib, name):
            raise ValueError('no such hash function: %s' % name)
        return getattr(hashlib, name)

    def hmac(self, key, message, hash='sha256'):
        """Return the HMAC of `message' under `key', using the hash function
        `hash' (default: sha256)."""
        md = self._get_hash(hash)
        return hmac.new(key, message, md).digest()

    def hkdf(self, password, salt, info, length, hash='sha256'):
        """HKDF key derivation function."""
        md = self._get_hash(hash)
        md_size = md().digest_size
        if length > 255*md_size:
            raise ValueError('can only generate keys up to 255*md_size bytes')
        if salt is None:
            salt = '\x00' * md_size
        prk = hmac.new(salt, password, md).digest()
        blocks = ['']
        nblocks = (length + md_size - 1) // md_size
        for i in range(nblocks):
            blocks.append(hmac.new(prk, blocks[i] + info + chr(i+1), md).digest())
        return ''.join(blocks)[:length]
