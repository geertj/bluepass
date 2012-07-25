#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import time
import gevent
import socket
from nose import SkipTest

from bluepass.crypto import CryptoProvider
from bluepass.locator import *
from bluepass.factory import create
from bluepass.test.unit import UnitTest


class TestLocator(UnitTest):

    @classmethod
    def setup_class(cls):
        super(TestLocator, cls).setup_class()
        zeroconf = create(ZeroconfLocationSource)
        if zeroconf is None or not zeroconf.isavailable():
            raise SkipTest('This test requires zeroconf to be available')
        cls.locator = Locator()
        cls.locator.add_source(zeroconf)
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
        assert len(result) == 1
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
            assert 'address' in addr
            assert isinstance(addr['address'], (str, unicode))
            assert 'port' in addr
            assert isinstance(addr['port'], int)
            assert addr['port'] == address[1]
        locator.unregister(node)
        gevent.sleep(5)
        result = locator.get_neighbors()
        assert isinstance(result, list)
        assert len(result) == 0

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
        assert len(result) == 1
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
        assert len(result) == 1
        result = result[0]
        assert 'properties' in result
        assert isinstance(result['properties'], dict)
        assert len(result['properties']) == 2
        assert 'foo' in result['properties']
        assert result['properties']['foo'] == 'bar'
        assert 'baz' in result['properties']
        assert result['properties']['baz'] == 'qux'
        locator.unregister(node)
