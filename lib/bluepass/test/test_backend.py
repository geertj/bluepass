#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import os
import time
import socket

from gevent import core
from bluepass.factory import create
from bluepass.test.unit import UnitTest, assert_raises
from bluepass.backend import start_backend, stop_backend, Backend
from bluepass.messagebus import MessageBusConnection, MessageBusError


class TestBackend(UnitTest):

    def setup(self):
        os.environ['HOME'] = self.tempdir()
        self.config = { 'debug': True, 'log_stdout': False }
        status, detail = start_backend(5, self.config)
        if not status:
            raise AssertionError('Could not start backend: %s: %s', detail)
        ipaddr, port, authtok = detail
        csock = socket.socket()
        csock.connect((ipaddr, port))
        self.connection = MessageBusConnection(csock, authtok)
        #self.connection._set_trace(file('/tmp/client.txt', 'w'))

    def teardown(self):
        self.connection.close()
        stop_backend(5)

    def test_db_created(self):
        dbname = os.path.join(os.environ['HOME'], '.bluepass', 'bluepass.db')
        assert os.access(dbname, os.R_OK)
        lockname = os.path.join(os.environ['HOME'], '.bluepass', 'bluepass.db-lock')
        assert os.access(dbname, os.R_OK)

    def test_multiple_startup(self):
        # start_backend() will not launch multiple backends
        status, detail = start_backend(Backend)
        assert status is False
        assert detail[0] == 'Exists'
        # create it ourselves. now the db locking prevents a startup
        orig = Backend.instance
        backend = create(Backend, self.config)
        status = backend.start(5)
        assert status is False
        assert backend.error_name == 'Locked'
        Backend.instance = orig

    def test_config(self):
        conn = self.connection
        config = conn.call_method('get_config')
        config['foo'] = 'bar'
        conn.call_method('update_config', config)
        config = conn.call_method('get_config')
        assert config['foo'] == 'bar'

    def test_lock_unlock_vault(self):
        conn = self.connection
        vault = conn.call_method('create_vault', 'My Vault', 'Passw0rd')
        version = conn.call_method('add_version', vault['id'], {'foo': 'bar'})
        assert isinstance(version, dict)
        assert 'id' in version
        conn.call_method('lock_vault', vault['id'])
        assert conn.call_method('vault_is_locked', vault['id'])
        err = assert_raises(MessageBusError, conn.call_method, 'get_version', vault['id'], version['id'])
        assert err.error_name == 'Locked'
        err = assert_raises(MessageBusError, conn.call_method, 'unlock_vault', vault['id'], 'Passw!rd')
        assert err.error_name == 'WrongPassword'
        conn.call_method('unlock_vault', vault['id'], 'Passw0rd')
        assert not conn.call_method('vault_is_locked', vault['id'])
        version2 = conn.call_method('get_version', vault['id'], version['id'])
        assert isinstance(version2, dict)
        assert version2['id'] == version['id']
        assert version2['foo'] == version['foo']

    def test_speed(self):
        conn = self.connection
        start = time.time()
        ncalls = 1000
        for i in range(ncalls):
            conn.call_method('get_config')
        end = time.time()
        print 'speed: %.2f calls/sec' % (1.0 * ncalls / (end - start))

    def test_generate_password(self):
        conn = self.connection
        pw = conn.call_method('generate_password', 'random', 20, '[0-9]')
        assert isinstance(pw, (str, unicode))
        assert len(pw) == 20
        assert pw.isdigit()
        pw = conn.call_method('generate_password', 'diceware', 6)
        assert isinstance(pw, (str, unicode))
        assert len(pw) >= 11
        assert pw.count(' ') == 5
