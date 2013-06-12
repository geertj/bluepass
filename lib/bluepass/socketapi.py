#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import socket
import logging

from bluepass import _version
from bluepass.util import misc
from bluepass.factory import instance, create
from bluepass.error import StructuredError
from bluepass.crypto import CryptoProvider
from bluepass.model import Model
from bluepass.passwords import PasswordGenerator
from bluepass.locator import Locator
from bluepass.messagebus import MessageBusHandler, MessageBusServer, method
from bluepass.syncapi import SyncAPIPublisher, SyncAPIClient, SyncAPIError


class PairingError(StructuredError):
    """Pairing error."""


class SocketAPIHandler(MessageBusHandler):
    """A message bus handler that implements our socket API."""

    # NOTE: all methods run in separate greenlets!

    def __init__(self):
        super(SocketAPIHandler, self).__init__()
        self.crypto = create(CryptoProvider)
        self.logger = logging.getLogger(__name__)
        instance(Model).add_callback(self._event_callback)
        instance(Locator).add_callback(self._event_callback)
        instance(SyncAPIPublisher).add_callback(self._event_callback)
        self.pairdata = {}

    def _event_callback(self, event, *args):
        # Forward the event over the message bus.
        instance(MessageBusServer).send_signal('client-*', event, *args)

    # Version

    @method()
    def get_version_info(self):
        version_info = {}
        for name in dir(_version):
            if name.startswith('_'):
                continue
            version_info[name] = getattr(_version, name)
        return version_info

    # Model methods

    @method()
    def get_config(self):
        return instance(Model).get_config()

    @method()
    def update_config(self, config):
        return instance(Model).update_config(config)

    @method()
    def create_vault(self, name, password, uuid=None, async=False):
        # Vault creation is time consuming because 3 RSA keys have
        # to be generated. Therefore an async variant is provided.
        model = instance(Model)
        if not async:
            return model.create_vault(name, password, uuid)
        if uuid is None:
            uuid = self.crypto.randuuid()
        self.early_response(uuid)
        try:
            vault = model.create_vault(name, password, uuid)
        except StructuredError as e:
            status = e[0]
            detail = e.asdict()
        except Exception:
            e = StructuredError.uncaught_exception()
            status = e[0]
            detail = e.asdict()
        else:
            status = 'OK'
            detail = vault
        self.connection.send_signal('VaultCreationComplete', uuid, status, detail)

    @method()
    def get_vault(self, uuid):
        return instance(Model).get_vault(uuid)

    @method()
    def get_vaults(self):
        return instance(Model).get_vaults()

    @method()
    def update_vault(self, vault):
        return instance(Model).update_vault(uuid, vault)

    @method()
    def delete_vault(self, vault):
        return instance(Model).delete_vault(vault)

    @method()
    def get_vault_statistics(self, uuid):
        return instance(Model).get_vault_statistics(uuid)

    @method()
    def unlock_vault(self, uuid, password):
        return instance(Model).unlock_vault(uuid, password)

    @method()
    def lock_vault(self, uuid):
        return instance(Model).lock_vault(uuid)

    @method()
    def vault_is_locked(self, uuid):
        return instance(Model).vault_is_locked(uuid)

    @method()
    def get_version(self, vault, uuid):
        return instance(Model).get_version(vault, uuid)

    @method()
    def get_versions(self, vault):
        return instance(Model).get_versions(vault)

    @method()
    def add_version(self, vault, version):
        return instance(Model).add_version(vault, version)

    @method()
    def update_version(self, vault, version):
        return instance(Model).update_version(vault, version)

    @method()
    def delete_version(self, vault, version):
        return instance(Model).delete_version(vault, version)

    @method()
    def get_version_history(self, vault, uuid):
        return instance(Model).get_version_history(vault, uuid)

    # Password methods

    @method()
    def generate_password(self, method, *args):
        return instance(PasswordGenerator).generate(method, *args)

    @method()
    def password_strength(self, method, *args):
        return instance(PasswordGenerator).strength(method, *args)

    # Locator methods

    @method()
    def get_neighbors(self):
        return instance(Locator).get_neighbors()

    # Pairing methods

    @method()
    def set_allow_pairing(self, timeout):
        publisher = instance(SyncAPIPublisher)
        publisher.set_allow_pairing(timeout)

    @method()
    def pair_neighbor_step1(self, node, source):
        locator = instance(Locator)
        neighbor = locator.get_neighbor(node, source)
        if neighbor is None:
            raise PairingError('NotFound', 'No such neighbor')
        visible = neighbor['properties'].get('visible')
        if not visible:
            raise PairingError('NotFound', 'Node not visible')
        vault = neighbor['vault']
        model = instance(Model)
        if model.get_vault(vault):
            raise PairingError('Exists', 'Vault already exists')
        # Don't keep the GUI blocked while we wait for remote approval.
        cookie = self.crypto.random(16).encode('hex')
        self.early_response(cookie)
        name = misc.gethostname()
        for addr in neighbor['addresses']:
            client = SyncAPIClient(addr)
            try:
                client.connect()
            except SyncAPIError as e:
                continue  # try next address
            try:
                kxid = client.pair_step1(vault, name)
            except SyncAPIError as e:
                status = e[0]
                detail = e.asdict()
            else:
                status = 'OK'
                detail = {}
                self.pairdata[cookie] = (kxid, neighbor, addr)
            self.connection.send_signal('PairNeighborStep1Completed', cookie,
                                        status, detail)
            client.close()
            break

    @method()
    def pair_neighbor_step2(self, cookie, pin, name, password):
        if cookie not in self.pairdata:
            raise PairingError('NotFound', 'No such key exchange ID')
        kxid, neighbor, addr = self.pairdata.pop(cookie)
        # Again don't keep the GUI blocked while we pair and do a full sync
        self.early_response()
        model = instance(Model)
        vault = model.create_vault(name, password, neighbor['vault'],
                                   notify=False)
        certinfo = { 'node': vault['node'], 'name': misc.gethostname() }
        keys = certinfo['keys'] = {}
        for key in vault['keys']:
            keys[key] = { 'key': vault['keys'][key]['public'],
                          'keytype': vault['keys'][key]['keytype'] }
        client = SyncAPIClient(addr)
        client.connect()
        try:
            peercert = client.pair_step2(vault['id'], kxid, pin, certinfo)
        except SyncAPIError as e:
            status = e[0]
            detail = e.asdict()
            model.delete_vault(vault)
        else:
            status = 'OK'
            detail = {}
            model.add_certificate(vault['id'], peercert)
            client.sync(vault['id'], model, notify=False)
            model.raise_event('VaultAdded', vault)
        self.connection.send_signal('PairNeighborStep2Completed', cookie,
                                    status, detail)
        client.close()
