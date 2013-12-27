#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from PyQt4.QtCore import Signal
from PyQt4.QtGui import QApplication

from . import qjsonrpc
from .qjsonrpc import *

__all__ = ['QtSocketApiError', 'QtSocketApiClient']


QtSocketApiError = QJsonRpcError


class QtSocketApiHandler(QJsonRpcHandler):
    """JSON-RPC message handler used by :class:`QtSocketApiClient`."""

    def __init__(self, notification_handler):
        super(QtSocketApiHandler, self).__init__()
        self._notification_handler = notification_handler

    @notification('*')
    def catch_all_notifications(self, *ignored):
        self._notification_handler(self.message)

    @request()
    def get_pairing_approval(self, name, vault, pin, kxid):
        message = self.message
        client = self.client
        mainwindow = QApplication.instance().mainWindow()
        def send_response(approved):
            reply = qjsonrpc.create_response(message, approved)
            client.send_message(reply)
        self.send_response = False
        mainwindow.showPairingApprovalDialog(name, vault, pin, kxid, send_response)


class QtSocketApiClient(QJsonRpcClient):
    """Qt frontend client for the Bluepass socket API."""

    def __init__(self, parent=None):
        handler = QtSocketApiHandler(self._notification_handler)
        super(QtSocketApiClient, self).__init__(handler, parent=parent)

    def _notification_handler(self, message):
        """Forward notifications to corresponding Qt signals."""
        assert message.get('id') is None
        method = message.get('method')
        assert method is not None
        signal = getattr(self, method, None)
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
        return self.call_method('get_version_info')

    def get_config(self):
        return self.call_method('get_config')

    def update_config(self, config):
        return self.call_method('update_config', config)

    def create_vault(self, name, password, async=False):
        return self.call_method('create_vault', name, password, async)

    def get_vault(self, uuid):
        return self.call_method('get_vault', uuid)

    def get_vaults(self):
        return self.call_method('get_vaults')

    def update_vault(self, vault):
        return self.call_method('update_vault', vault)

    def delete_vault(self, vault):
        return self.call_method('delete_vault', vault)

    def get_vault_statistics(self, uuid):
        return self.call_method('get_vault_statistics', uuid)

    def unlock_vault(self, uuid, password):
        return self.call_method('unlock_vault', uuid, password)

    def lock_vault(self, uuid):
        return self.call_method('lock_vault', uuid)

    def vault_is_locked(self, uuid):
        return self.call_method('vault_is_locked', uuid)

    def get_version(self, vault, uuid):
        return self.call_method('get_version', vault, uuid)

    def get_versions(self, vault):
        return self.call_method('get_versions', vault)

    def add_version(self, vault, version):
        return self.call_method('add_version', vault, version)

    def update_version(self, vault, version):
        return self.call_method('update_version', vault, version)

    def delete_version(self, vault, version):
        return self.call_method('delete_version', vault, version)
    
    def get_version_history(self, vault, uuid):
        return self.call_method('get_version_history', vault, uuid)

    def generate_password(self, method, *args):
        return self.call_method('generate_password', method, *args)

    def password_strength(self, method, *args):
        return self.call_method('password_strength', method, *args)

    def get_neighbors(self):
        return self.call_method('get_neighbors')

    def locator_is_available(self):
        return self.call_method('locator_is_available')

    def set_allow_pairing(self, timeout):
        return self.call_method('set_allow_pairing', timeout)

    def pair_neighbor_step1(self, node, source):
        return self.call_method('pair_neighbor_step1', node, source)

    def pair_neighbor_step2(self, cookie, pin, name, password):
        return self.call_method('pair_neighbor_step2', cookie, pin, name, password)
