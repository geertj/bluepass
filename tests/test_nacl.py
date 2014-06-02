#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from support import *
from bluepass import nacl


class TestNacl(UnitTest):
    """Unit test suite for the nacl module."""

    def test_sign(self):
        msg = b'Hello, world!'
        pk, sk = nacl.sign_keypair()
        self.assertEqual(len(pk), nacl.sign_PUBLICKEYBYTES)
        self.assertEqual(len(sk), nacl.sign_SECRETKEYBYTES)
        sig = nacl.sign(msg, sk)
        self.assertTrue(nacl.sign_verify(msg, sig, pk))
        sig = bytearray(sig)
        msg = bytearray(msg)
        sig[0] ^= 0xff; self.assertFalse(nacl.sign_verify(msg, sig, pk))
        sig[0] ^= 0xff; self.assertTrue(nacl.sign_verify(msg, sig, pk))
        msg[0] ^= 0xff; self.assertFalse(nacl.sign_verify(msg, sig, pk))
        msg[0] ^= 0xff; self.assertTrue(nacl.sign_verify(msg, sig, pk))

    def test_stream(self):
        msg = b'Hello, world!'
        key = nacl.randombytes(nacl.stream_KEYBYTES)
        nonce = nacl.randombytes(nacl.stream_NONCEBYTES)
        enc = nacl.stream_xor(msg, nonce, key)
        self.assertIsInstance(enc, bytes)
        self.assertEqual(len(msg), len(enc))
        msg2 = nacl.stream_xor(enc, nonce, key)
        self.assertEqual(msg, msg2)

    def test_scalarmult(self):
        x = nacl.randombytes(nacl.scalarmult_SCALARBYTES)
        y = nacl.randombytes(nacl.scalarmult_SCALARBYTES)
        gX = nacl.scalarmult_base(x)
        self.assertEqual(len(gX), nacl.scalarmult_BYTES)
        gY = nacl.scalarmult_base(y)
        self.assertEqual(len(gY), nacl.scalarmult_BYTES)
        gXY = nacl.scalarmult(y, gX)
        self.assertEqual(len(gXY), nacl.scalarmult_BYTES)
        gYX = nacl.scalarmult(x, gY)
        self.assertEqual(len(gYX), nacl.scalarmult_BYTES)
        self.assertEqual(gXY, gYX)

    def test_onetimeauth(self):
        msg = b'Hello, world!'
        key = nacl.randombytes(nacl.lookup('onetimeauth_KEYBYTES'))
        auth = nacl.onetimeauth(msg, key)
        self.assertIsInstance(auth, bytes)
        self.assertTrue(nacl.onetimeauth_verify(auth, msg, key))
        self.assertEqual(len(auth), nacl.lookup('onetimeauth_BYTES'))
        msg = bytearray(msg)
        key = bytearray(key)
        auth = bytearray(auth)
        msg[0] ^= 0xff; self.assertFalse(nacl.onetimeauth_verify(auth, msg, key))
        msg[0] ^= 0xff; self.assertTrue(nacl.onetimeauth_verify(auth, msg, key))
        key[0] ^= 0xff; self.assertFalse(nacl.onetimeauth_verify(auth, msg, key))
        key[0] ^= 0xff; self.assertTrue(nacl.onetimeauth_verify(auth, msg, key))
        auth[0] ^= 0xff; self.assertFalse(nacl.onetimeauth_verify(auth, msg, key))
        auth[0] ^= 0xff; self.assertTrue(nacl.onetimeauth_verify(auth, msg, key))

    def test_hash(self):
        msg = b'Foo bar baz'
        h = nacl.hash(msg)
        self.assertIsInstance(h, bytes)
        self.assertEqual(len(h), nacl.lookup('hash_BYTES'))


if __name__ == '__main__':
    unittest.main()
