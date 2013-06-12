#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import sys
from subprocess import Popen, PIPE

from bluepass.crypto import CryptoProvider, CryptoError, dhparams
from bluepass.test.unit import UnitTest

from nose import SkipTest
from nose.tools import assert_raises


class CryptoTest(UnitTest):

    @classmethod
    def setup_class(cls):
        super(CryptoTest, cls).setup_class()
        cls.provider = CryptoProvider()

    def load_vectors(self, relname, start):
        dname = os.path.split(__file__)[0]
        fname = os.path.join(dname, relname)
        fin = open(fname)
        vectors = []
        while True:
            line = fin.readline()
            if not line:
                break
            line = line.rstrip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('%s=' % start):
                vectors.append({})
            if '=' not in line or not vectors:
                raise RuntimeError('Illegal test vector format: %s' % fname)
            key, value = line.split('=')
            value = value.decode('hex')
            vectors[-1][key] = value
        return vectors


class TestCrypto(CryptoTest):

    @classmethod
    def setup_class(cls):
        super(TestCrypto, cls).setup_class()
        cls.rsakeys = [ (sz, cls.provider.rsa_genkey(sz))
                     for sz in (2048, 3072) ]

    def test_rsa_encrypt(self):
        cp = self.provider
        for keysize,key in self.rsakeys:
            for size in range(keysize/8 - 41):
                pt = os.urandom(size)
                ct = cp.rsa_encrypt(pt, key[1])
                assert len(ct) == keysize/8
                pt2 = cp.rsa_decrypt(ct, key[0])
                assert pt == pt2

    def test_rsa_sign(self):
        cp = self.provider
        for keysize,key in self.rsakeys:
            for size in range(0, 10000, 100):
                msg = os.urandom(size)
                sig = cp.rsa_sign(msg, key[0])
                assert cp.rsa_verify(msg, sig, key[1])

    def test_rsa_encrypt_vectors(self):
        cp = self.provider
        if not hasattr(cp.engine, '_insert_random_bytes'):
            raise SkipTest('RSA-OAEP tests require -DTEST_BUILD')
        vectors = self.load_vectors('vectors/rsa-oaep.txt', start='PT')
        for vector in vectors:
            cp.engine._insert_random_bytes(vector['SEED'])
            ct = cp.rsa_encrypt(vector['PT'], vector['PUBKEY'], 'oaep')
            assert vector['CT'] == ct
            pt = cp.rsa_decrypt(vector['CT'], vector['PRIVKEY'], 'oaep')
            assert pt == vector['PT']

    def test_rsa_sign_vectors(self):
        cp = self.provider
        if not hasattr(cp.engine, '_insert_random_bytes'):
            raise SkipTest('RSA-PSS tests require -DTEST_BUILD')
        vectors = self.load_vectors('vectors/rsa-pss.txt', start='MSG')
        for vector in vectors:
            cp.engine._insert_random_bytes(vector['SALT'])
            sig = cp.rsa_sign(vector['MSG'], vector['PRIVKEY'], 'pss-sha1')
            assert sig == vector['SIG']
            assert cp.rsa_verify(vector['MSG'], vector['SIG'],
                                 vector['PUBKEY'], 'pss-sha1')

    def test_dh_exchange(self):
        cp = self.provider
        params = dhparams['skip2048']
        kp1 = cp.dh_genkey(params)
        kp2 = cp.dh_genkey(params)
        secret1 = cp.dh_compute(params, kp1[0], kp2[1])
        secret2 = cp.dh_compute(params, kp2[0], kp1[1])
        assert secret1 == secret2

    def test_aes_encrypt(self):
        cp = self.provider
        for size in range(100):
            for keysize in (16, 24, 32):
                key = os.urandom(keysize)
                iv = os.urandom(16)
                cleartext = os.urandom(size)
                ciphertext = cp.aes_encrypt(cleartext, key, iv)
                padlen = (16 - len(cleartext)%16)
                assert len(ciphertext) == len(cleartext) + padlen
                clear2 = cp.aes_decrypt(ciphertext, key, iv)
                assert cleartext == clear2

    def test_aes_vectors(self):
        cp = self.provider
        vectors = self.load_vectors('vectors/aes-cbc-pkcs7.txt', start='PT')
        for vector in vectors:
            ct = cp.aes_encrypt(vector['PT'], vector['KEY'], vector['IV'])
            assert ct == vector['CT']
            pt = cp.aes_decrypt(vector['CT'], vector['KEY'], vector['IV'])
            assert pt == vector['PT']

    def test_pbkdf2_vectors(self):
        cp = self.provider
        vectors = self.load_vectors('vectors/pbkdf2.txt', start='PASSWORD')
        for vector in vectors:
            key = cp.pbkdf2(vector['PASSWORD'], vector['SALT'],
                            int(vector['ITER']), int(vector['KEYLEN']),
                            'hmac-sha1')
            assert key == vector['KEY']

    def test_pbkdf2_size(self):
        cp = self.provider
        for sz in range(100):
            key = cp.pbkdf2('password', 'salt', 1, sz)
            assert len(key) == sz

    def test_pbkdf2_error_empty_password(self):
        cp = self.provider
        assert_raises(CryptoError, cp.pbkdf2, '', 'salt', 1, 1)

    def test_pbkdf2_error_empty_salt(self):
        cp = self.provider
        assert_raises(CryptoError, cp.pbkdf2, 'password', '', 1, 1)

    def test_pbkdf2_error_zero_iter(self):
        cp = self.provider
        assert_raises(CryptoError, cp.pbkdf2, 'password', 'salt', 0, 1)

    def test_pbkdf2_speed(self):
        cp = self.provider
        speed = cp.pbkdf2_speed()

    def test_hkdf_vectors(self):
        cp = self.provider
        vectors = self.load_vectors('vectors/hkdf.txt', start='PASSWORD')
        for vector in vectors:
            key = cp.hkdf(vector['PASSWORD'], vector['SALT'], vector['INFO'],
                              int(vector['KEYLEN']), vector['HASH'])
            assert key == vector['KEY']

    def test_random_bytes(self):
        cp = self.provider
        rnd = cp.random(10)
        assert isinstance(rnd, str)
        assert len(rnd) == 10

    def test_random_with_alphabet(self):
        cp = self.provider
        rnd = cp.random(10, '0123456789')
        assert isinstance(rnd, str)
        assert len(rnd) == 10
        assert rnd.isdigit()
        rnd = cp.random(10, u'0123456789')
        assert isinstance(rnd, unicode)
        assert len(rnd) == 10
        assert rnd.isdigit()
        rnd = cp.random(5, ['01', '23', '45', '67', '89'])
        assert isinstance(rnd, str)
        assert len(rnd) == 10
        assert rnd.isdigit()
        rnd = cp.random(5, ['01', '23', '45', '67', '89'], '0')
        assert isinstance(rnd, str)
        assert len(rnd) == 14
        assert rnd.isdigit()
        rnd = cp.random(5, [u'01', u'23', u'45', u'67', u'89'], u'0')
        assert isinstance(rnd, unicode)
        assert len(rnd) == 14
        assert rnd.isdigit()
