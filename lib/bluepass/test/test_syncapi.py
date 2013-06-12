#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import time

from gevent import socket
from gevent.event import Event

from bluepass.test.unit import UnitTest
from bluepass.factory import create, instance
from bluepass.database import Database
from bluepass.model import Model
from bluepass.syncapi import *
from bluepass.messagebus import *


class MBTestHandler(MessageBusHandler):

    @method()
    def get_pairing_approval(self, name, uuid, pin, kxid):
        self.name = name
        self.pin = pin
        return True, {}


class TestSyncAPI(UnitTest):

    def test_pair_and_sync(self):
        # Create two databases and two models
        database1 = Database(self.tempfile())
        model1 = create(Model, database1)
        assert instance(Model) is model1
        vault1 = model1.create_vault('Vault1', 'Passw0rd')
        database2 = Database(self.tempfile())
        model2 = Model(database2)
        vault2 = model2.create_vault('Vault2', 'Passw0rd', uuid=vault1['id'])
        # Start a message bus server and client connection
        lsock = socket.socket()
        lsock.bind(('localhost', 0))
        lsock.listen(2)
        mbserver = create(MessageBusServer, lsock, 'S3cret', None)
        #mbserver.set_trace('/tmp/server.txt')
        mbserver.start()
        csock = socket.socket()
        csock.connect(lsock.getsockname())
        mbhandler = MBTestHandler()
        mbclient = MessageBusConnection(csock, 'S3cret', mbhandler)
        #mbclient.set_trace('/tmp/client.txt')
        mbclient.authenticate()  # XXX
        # Start the syncapi
        lsock = socket.socket()
        lsock.bind(('localhost', 0))
        lsock.listen(2)
        address = lsock.getsockname()
        syncapp = SyncAPIApplication()
        syncapp.allow_pairing = True
        server = SyncAPIServer(lsock, syncapp)
        server.start()
        # Pair with vault1
        client = SyncAPIClient(lsock.getsockname())
        client.connect()
        kxid = client.pair_step1(vault1['id'], 'foo')
        assert kxid is not None
        assert mbhandler.name == 'foo'
        certinfo = { 'name': 'node2', 'node': vault2['node'] }
        keys = certinfo['keys'] = {}
        for key in vault2['keys']:
            keys[key] = { 'key': vault2['keys'][key]['public'],
                          'keytype': vault2['keys'][key]['keytype'] }
        peercert = client.pair_step2(vault1['id'], kxid, mbhandler.pin, certinfo)
        assert isinstance(peercert, dict)
        assert model1.check_certinfo(peercert)[0]
        model2.add_certificate(vault2['id'], peercert)
        # Sync
        version1 = model1.add_version(vault1['id'], {'foo': 'bar'})
        client.sync(vault1['id'], model2)
        version2 = model2.get_version(vault1['id'], version1['id'])
        assert version2 is not None
        assert version2['foo'] == 'bar'
