#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import time
import socket
import signal

from gevent import core
from .unit import UnitTest, assert_raises

from bluepass.factory import create
from bluepass.database import DatabaseError
from bluepass.backend import Backend, BackendController
from bluepass.messagebus import MessageBusConnection, MessageBusError
from bluepass.util import misc as util


class TestBackend(UnitTest):

    def setup(self):
        os.environ['HOME'] = self.tempdir()
        authtok = os.urandom(16).encode('hex')
        self.config = { 'debug': True, 'log_stdout': False,
                        'auth_token': authtok }
        # XXX: Create a Posix/Windows controller? For now just os.spawnve()
        # and a timeout.
        ctrl = BackendController(self.config)
        cmd, args, env = ctrl.startup_info()
        self.backend_pid = os.spawnve(os.P_NOWAIT, cmd, args, env)
        time.sleep(1)
        addrspec = ctrl.backend_address()
        addr = util.parse_address(addrspec)
        csock = util.create_connection(addr)
        self.connection = MessageBusConnection(csock, authtok)

    def teardown(self):
        self.connection.close()
        time.sleep(0.5)
        os.kill(self.backend_pid, signal.SIGTERM)
        time.sleep(0.5)

    def test_db_created(self):
        dbname = os.path.join(os.environ['HOME'], '.bluepass', 'bluepass.db')
        assert os.access(dbname, os.R_OK)
        lockname = os.path.join(os.environ['HOME'], '.bluepass', 'bluepass.db-lock')
        assert os.access(dbname, os.R_OK)

    def test_multiple_startup(self):
        backend = Backend(self.config)
        exc = assert_raises(DatabaseError, backend.run)
        assert exc.error_name == 'Locked'

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
        print('speed: %.2f calls/sec' % (1.0 * ncalls / (end - start)))

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
