#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os

from .unit import UnitTest, SkipTest
from bluepass.factory import create
from bluepass.keyring import Keyring, KeyringError


class TestKeyring(UnitTest):

    @classmethod
    def setup_class(cls):
        super(TestKeyring, cls).setup_class()
        keyring = create(Keyring)
        if keyring is None or not keyring.isavailable():
            raise SkipTest('This test requires a Keyring to be avaialble')
        cls.keyring = keyring

    def test_roundtrip(self):
        key = os.urandom(8).encode('hex')
        secret = os.urandom(32)
        self.keyring.store(key, secret)
        value = self.keyring.retrieve(key)
        assert value == secret

    def test_overwrite(self):
        key = os.urandom(8).encode('hex')
        for i in range(10):
            secret = os.urandom(i)
            self.keyring.store(key, secret)
            value = self.keyring.retrieve(key)
            assert value == secret
