#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from PyQt4.QtCore import Signal
from PyQt4.QtGui import QApplication

from gruvi import jsonrpc
from bluepass.rpckit import RpcHandler, route
from .qjsonrpc import QJsonRpcClient, QJsonRpcError

__all__ = ['ControlApiError', 'ControlApiClient']


ControlApiError = QJsonRpcError


class ControlApiHandler(RpcHandler):
    """JSON-RPC message handler used by :class:`ControlApiClient`."""

    Local = type('Object', (object,), {})

    def __init__(self, notification_handler):
        super(ControlApiHandler, self).__init__()
        self._notification_handler = notification_handler

    def __call__(self, message, client):
        # Adapt call signature to QJsonRpcClient
        super(ControlApiHandler, self).__call__(message, None, client)

    def method_not_found(self, method, *args):
        if self.message.get('id'):
            return  # method call
        self._notification_handler(method, *args)

    @route()
    def get_pairing_approval(self, name, vault, pin, kxid):
        message = self.message
        protocol = self.protocol
        mainwindow = QApplication.instance().mainWindow()
        def send_response(approved):
            reply = jsonrpc.create_response(message, approved)
            protocol.send_message(reply)
        self.delay_response()
        mainwindow.showPairingApprovalDialog(name, vault, pin, kxid, send_response)

    @route()
    def approve_client(self, info):
        message = self.message
        protocol = self.protocol
        mainwindow = QApplication.instance().mainWindow()
        def send_response(approved):
            reply = jsonrpc.create_response(message, approved)
            protocol.send_message(reply)
        self.delay_response()
        mainwindow.showApproveClientDialog(info, send_response)


class ControlApiClient(QJsonRpcClient):
    """Qt frontend client for the Bluepass control API."""

    def __init__(self, parent=None):
        handler = ControlApiHandler(self._forward_notifications)
        super(ControlApiClient, self).__init__(handler, parent=parent)

    def _forward_notifications(self, method, *args):
        """Forward notifications to corresponding Qt signals."""
        signal = getattr(self, method, None)
        if signal and hasattr(signal, 'emit'):
            signal.emit(*args)

    VaultCreated = Signal(dict)
    VaultDeleted = Signal(str)
    VaultCreationComplete = Signal(str, bool, str)
    VaultLocked = Signal(str)
    VaultUnlocked = Signal(str)
    SecretsAdded = Signal(str, list)
    NeighborDiscovered = Signal(dict)
    NeighborUpdated = Signal(dict)
    NeighborDisappeared = Signal(dict)
    AllowPairingStarted = Signal(int)
    AllowPairingEnded = Signal()
    PairNeighborStep1Completed = Signal(str, bool, str)
    PairNeighborStep2Completed = Signal(str, bool, str)
    PairingComplete = Signal(str)

    def login(self, auth_token):
        return self.call_method('login', auth_token)

    def get_version_info(self):
        return self.call_method('get_version_info')

    def create_config(self, template):
        return self.call_method('create_config', template)

    def get_config(self, name):
        return self.call_method('get_config', name)

    def update_config(self, name, update):
        return self.call_method('update_config', name, update)

    def create_vault(self, template):
        return self.call_method('create_vault', template)

    def get_vault(self, uuid):
        return self.call_method('get_vault', uuid)

    def get_vaults(self):
        return self.call_method('get_vaults')

    def update_vault(self, uuid, vault):
        return self.call_method('update_vault', uuid, vault)

    def delete_vault(self, uuid):
        return self.call_method('delete_vault', uuid)

    def get_vault_statistics(self, uuid):
        return self.call_method('get_vault_statistics', uuid)

    def unlock_vault(self, uuid, password, cache_fields=[]):
        return self.call_method('unlock_vault', uuid, password, cache_fields)

    def lock_vault(self, uuid):
        return self.call_method('lock_vault', uuid)

    def get_vault_status(self, uuid):
        return self.call_method('get_vault_status', uuid)

    def get_secret(self, vault, uuid):
        return self.call_method('get_secret', vault, uuid)

    def get_secrets(self, vault):
        return self.call_method('get_secrets', vault)

    def create_secret(self, vault, template):
        return self.call_method('create_secret', vault, template)

    def update_secret(self, vault, uuid, update):
        return self.call_method('update_secret', vault, uuid, update)

    def delete_secret(self, vault, uuid):
        return self.call_method('delete_secret', vault, uuid)
    
    def get_secret_history(self, vault, uuid):
        return self.call_method('get_secret_history', vault, uuid)

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
