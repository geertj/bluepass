#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import time
import socket

from bluepass.backend import BackendController
from bluepass.util import misc as util

from PyQt4.QtCore import QObject, QProcess, Signal


class QtBackendController(BackendController):

    def __init__(self, options):
        super(QtBackendController, self).__init__(options)
        self.process = None

    def start(self):
        if self.process is not None:
            raise RuntimeError('Backend was already started')
        executable, args, env = self.startup_info()
        proc = self.process = QProcess()
        proc.setProcessChannelMode(QProcess.ForwardedChannels)
        env = ['{}={}'.format(k, v) for (k,v) in env.items()]
        proc.setEnvironment(env)
        proc.start(executable, args[1:])
        proc.waitForStarted()

    def stop(self):
        if self.process is None:
            raise RuntimeError('Backend is not running')
        proc = self.process
        now = time.time()
        end_time = now + self.timeout
        while True:
            proc.terminate()
            time.sleep(0.1)
            if proc.state() == QProcess.NotRunning:
                break
            now = time.time()
            if now > end_time:
                break
        if proc.state() != QProcess.NotRunning:
            proc.kill()
            time.sleep(0.1)
        self.process = None

    def connect(self):
        sock = None
        now = time.time()
        end_time = now + self.timeout
        while True:
            addrspec = self.backend_address()
            if addrspec:
                addr = util.parse_address(addrspec)
                try:
                    timeout = max(0.1, (end_time-now)/2)
                    sock = util.create_connection(addr, timeout)
                except socket.error:
                    pass
                else:
                    break
            now = time.time()
            if now > end_time:
                break
            time.sleep(0.1)
        return sock


class BackendProxy(QObject):

    def __init__(self, connection, parent=None):
        super(BackendProxy, self).__init__(parent)
        self.connection = connection
        connection.handler.set_catchall_signal_handler(self._signal_handler)

    def _call_method(self, name, *args):
        return self.connection.call_method(name, *args)

    def _signal_handler(self, message, connection):
        """Called for any signal that arrives.
        
        The signal is passed on as a Qt Signal().
        """
        name = message['method']
        signal = getattr(self, name, None)
        if signal and hasattr(signal, 'emit'):
            signal.emit(*message.get('params', ()))

    VaultAdded = Signal(dict)
    VaultRemoved = Signal(dict)
    VaultCreationComplete = Signal(str, str, dict)
    VaultLocked = Signal(dict)
    VaultUnlocked = Signal(dict)
    VersionsAdded = Signal(str, list)
    NeighborDiscovered = Signal(dict)
    NeighborUpdated = Signal(dict)
    NeighborDisappeared = Signal(dict)
    AllowPairingStarted = Signal(int)
    AllowPairingEnded = Signal()
    PairNeighborStep1Completed = Signal(str, str, dict)
    PairNeighborStep2Completed = Signal(str, str, dict)
    PairingComplete = Signal(str)

    def get_version_info(self):
        return self._call_method('get_version_info')

    def get_config(self):
        return self._call_method('get_config')

    def update_config(self, config):
        return self._call_method('update_config', config)

    def create_vault(self, name, password, async=False):
        return self._call_method('create_vault', name, password, async)

    def get_vault(self, uuid):
        return self._call_method('get_vault', uuid)

    def get_vaults(self):
        return self._call_method('get_vaults')

    def update_vault(self, vault):
        return self._call_method('update_vault', vault)

    def delete_vault(self, vault):
        return self._call_method('delete_vault', vault)

    def get_vault_statistics(self, uuid):
        return self._call_method('get_vault_statistics', uuid)

    def unlock_vault(self, uuid, password):
        return self._call_method('unlock_vault', uuid, password)

    def lock_vault(self, uuid):
        return self._call_method('lock_vault', uuid)

    def vault_is_locked(self, uuid):
        return self._call_method('vault_is_locked', uuid)

    def get_version(self, vault, uuid):
        return self._call_method('get_version', vault, uuid)

    def get_versions(self, vault):
        return self._call_method('get_versions', vault)

    def add_version(self, vault, version):
        return self._call_method('add_version', vault, version)

    def update_version(self, vault, version):
        return self._call_method('update_version', vault, version)

    def delete_version(self, vault, version):
        return self._call_method('delete_version', vault, version)
    
    def get_version_history(self, vault, uuid):
        return self._call_method('get_version_history', vault, uuid)

    def generate_password(self, method, *args):
        return self._call_method('generate_password', method, *args)

    def password_strength(self, method, *args):
        return self._call_method('password_strength', method, *args)

    def get_neighbors(self):
        return self._call_method('get_neighbors')

    def set_allow_pairing(self, timeout):
        return self._call_method('set_allow_pairing', timeout)

    def pair_neighbor_step1(self, node, source):
        return self._call_method('pair_neighbor_step1', node, source)

    def pair_neighbor_step2(self, cookie, pin, name, password):
        return self._call_method('pair_neighbor_step2', cookie, pin, name,
                                 password)
