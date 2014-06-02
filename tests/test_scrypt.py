#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from support import *
from bluepass import scrypt


class TestNacl(UnitTest):
    """Unit test suite for the nacl module."""

    def test_scrypt(self):
        password = b'Secr3t'
        salt = b'Foo'
        N = 2**12; r = 8; p = 1; l = 16
        key = scrypt.scrypt(password, salt, N, r, p, l)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), l)


if __name__ == '__main__':
    unittest.main()
