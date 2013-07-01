#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import time
import gevent
import socket
from nose import SkipTest

from bluepass import platform
from bluepass.crypto import CryptoProvider
from bluepass.locator import *
from bluepass.factory import singleton
from bluepass.test.unit import UnitTest


class TestLocator(UnitTest):

    @classmethod
    def setup_class(cls):
        super(TestLocator, cls).setup_class()
        sources = platform.get_location_sources()
        if not sources:
            raise SkipTest('No location sources avaialble')
        cls.locator = Locator()
        cls.locator.add_source(sources[0]())
        cls.crypto = CryptoProvider()

    def test_register(self):
        locator = self.locator
        node = self.crypto.randuuid()
        nodename = 'My Node'
        vault = self.crypto.randuuid()
        vaultname = 'My Vault'
        address = ('1.2.3.4', 100)
        locator.register(node, nodename, vault, vaultname, address)
        gevent.sleep(5)
        result = locator.get_neighbors()
        assert isinstance(result, list)
        assert len(result) > 0
        result = result[0]
        assert isinstance(result, dict)
        assert 'node' in result
        assert result['node'] == node
        assert 'nodename' in result
        assert result['nodename'] == nodename
        assert 'vault' in result
        assert result['vault'] == vault
        assert 'vaultname' in result
        assert result['vaultname'] == vaultname
        assert 'source' in result
        assert result['source'] == 'LAN'
        assert 'properties' in result
        assert isinstance(result['properties'], dict)
        assert len(result['properties']) == 0
        assert 'addresses' in result
        assert isinstance(result['addresses'], list)
        assert len(result['addresses']) >= 1
        for addr in result['addresses']:
            assert isinstance(addr, dict)
            assert 'family' in addr
            assert isinstance(addr['family'], int)
            assert addr['family'] in (socket.AF_INET, socket.AF_INET6)
            assert 'addr' in addr
            assert isinstance(addr['addr'], tuple)
            assert isinstance(addr['addr'][0], (str, unicode))
            assert isinstance(addr['addr'][1], int)
            assert addr['addr'][1] == address[1]
        locator.unregister(node)
        gevent.sleep(5)
        result = locator.get_neighbors()
        assert isinstance(result, list)
        #assert len(result) == 0

    def test_set_property(self):
        locator = self.locator
        node = self.crypto.randuuid()
        nodename = 'My Node'
        vault = self.crypto.randuuid()
        vaultname = 'My Vault'
        address = ('1.2.3.4', 100)
        locator.register(node, nodename, vault, vaultname, address)
        gevent.sleep(5)
        locator.set_property(node, 'foo', 'bar')
        gevent.sleep(5)
        result = locator.get_neighbors()
        assert isinstance(result, list)
        assert len(result) > 0
        result = result[0]
        assert 'properties' in result
        assert isinstance(result['properties'], dict)
        assert len(result['properties']) == 1
        assert 'foo' in result['properties']
        assert result['properties']['foo'] == 'bar'
        locator.set_property(node, 'baz', 'qux')
        gevent.sleep(5)
        result = locator.get_neighbors()
        gevent.sleep(5)
        assert isinstance(result, list)
        assert len(result) > 0
        result = result[0]
        assert 'properties' in result
        assert isinstance(result['properties'], dict)
        assert len(result['properties']) == 2
        assert 'foo' in result['properties']
        assert result['properties']['foo'] == 'bar'
        assert 'baz' in result['properties']
        assert result['properties']['baz'] == 'qux'
        locator.unregister(node)
