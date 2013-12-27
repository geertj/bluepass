#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import logging
import binascii

from bluepass import _version, util
from bluepass.factory import instance
from bluepass.error import StructuredError
from bluepass.crypto import CryptoProvider
from bluepass.model import Model
from bluepass.passwords import PasswordGenerator
from bluepass.locator import Locator
from bluepass.syncapi import SyncAPIPublisher, SyncAPIClient, SyncAPIError

import gruvi
from gruvi import jsonrpc
from gruvi.jsonrpc import *


class PairingError(StructuredError):
    """Pairing error."""


def method():
    """Decorate a method."""
    def decorate(method):
        method.method = True
        return method
    return decorate


class JsonRpcHandler(object):
    """JSON-RPC procotol handler."""

    def __init__(self):
        self.local = gruvi.local()

    @property
    def message(self):
        return self.local.message

    @property
    def protocol(self):
        return self.local.protocol

    @property
    def transport(self):
        return self.local.transport

    def send_response(self, result):
        response = jsonrpc.create_response(self.message, result)
        self.protocol.send_message(self.transport, response)
        self.local.response_sent = True

    def send_notification(self, name, *args):
        message = jsonrpc.create_notification(name, args)
        self.protocol.send_message(self.transport, message)

    def __call__(self, message, protocol, transport):
        method = message.get('method')
        if method is None:
            return
        handler = getattr(self, method)
        if handler is None or not getattr(handler, 'method', False):
            return
        args = message.get('params', ())
        self.local.message = message
        self.local.protocol = protocol
        self.local.transport = transport
        self.local.response_sent = False
        response = None
        try:
            result = handler(*args)
        except StructuredError as e:
            if not self.local.response_sent:
                response = jsonrpc.create_error(message, error=e.asdict())
        else:
            if not self.local.response_sent:
                response = jsonrpc.create_response(message, result)
        return response


class SocketAPIHandler(JsonRpcHandler):
    """A message bus handler that implements our socket API."""

    # NOTE: all methods run in separate fibers!

    def __init__(self):
        super(SocketAPIHandler, self).__init__()
        self.crypto = instance(CryptoProvider)
        self.logger = logging.getLogger(__name__)
        self.pairdata = {}

    # Version

    @method()
    def get_version_info(self):
        """Get version information.

        Returns a dictionary containing at least the key "version".
        """
        version_info = {}
        for name in dir(_version):
            if name.startswith('_'):
                continue
            version_info[name] = getattr(_version, name)
        return version_info

    # Model methods

    @method()
    def get_config(self):
        """Return the configuration object.

        The configuration object is a dictionary that can be used by frontends
        to store configuration data.
        """
        return instance(Model).get_config()

    @method()
    def update_config(self, config):
        """Update the configuration object."""
        return instance(Model).update_config(config)

    @method()
    def create_vault(self, name, password, async=False):
        """Create a new vault.

        The vault will have the name *name*. The vault's private keys will be
        encrypted with *password*.

        The *async* parameter specifies if the vault creation needs to be
        asynchronous. If it is set to False, then the vault is created
        synchronously and it is returned as a dictionary. If async is set to
        True, then this will return the UUID of the vault as a stirng. Once the
        vault has been created, the ``VaultCreationComplete`` signal will be
        raised. The signal has three arguments: the UUID, a status code, and a
        detailed message.

        Creating a vault requires the backend to generate 3 RSA keys. This can
        be a time consuming process. Therefore it is recommended to use
        asynchronous vault creation in user interfaces.
        """
        # Vault creation is time consuming because 3 RSA keys have
        # to be generated. Therefore an async variant is provided.
        model = instance(Model)
        if not async:
            return model.create_vault(name, password)
        uuid = self.crypto.randuuid()
        self.send_response(uuid)
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
        self.send_notification('VaultCreationComplete', uuid, status, detail)

    @method()
    def get_vault(self, uuid):
        """Return the vault with UUID *uuid*.

        The result value is a dictionary containing the vault metadata, or
        ``None`` if the vault was not found.
        """
        return instance(Model).get_vault(uuid)

    @method()
    def get_vaults(self):
        """Return a list of all vaults.

        The result value is a list if dictionaries containing vault metadata.
        """
        return instance(Model).get_vaults()

    @method()
    def update_vault(self, vault):
        """Update a vault's metadata.

        The *vault* parameter must be a dictionary. The recommended way to use
        this function is to use :meth:`get_vault` to retrieve the metadata,
        make updates, make updates to it, and the use this method to save the
        updates.

        On success, nothing is returned. On error, an exception is raised.
        """
        return instance(Model).update_vault(uuid, vault)

    @method()
    def delete_vault(self, vault):
        """Delete a vault and all its items.

        The *vault* parameter must be a vault metadata dictionary returned by
        :meth:`get_vault`.
        """
        return instance(Model).delete_vault(vault)

    @method()
    def get_vault_statistics(self, uuid):
        """Return statistics about a vault.

        The return value is a dictionary.
        """
        return instance(Model).get_vault_statistics(uuid)

    @method()
    def unlock_vault(self, uuid, password):
        """Unlock a vault.

        The vault *uuid* is unlocked using *password*. This decrypts the
        private keys that are stored in the database and stored them in
        memory.

        On error, an exception is raised. It is not an error to unlock a vault
        that is already unlocked.
        """
        return instance(Model).unlock_vault(uuid, password)

    @method()
    def lock_vault(self, uuid):
        """Lock a vault.

        This destroys the decrypted private keys and any other decrypted items
        that are cached.

        It is not an error to lock a vault that is already locked.
        """
        return instance(Model).lock_vault(uuid)

    @method()
    def vault_is_locked(self, uuid):
        """Return whether or not the vault *uuid* is locked."""
        return instance(Model).vault_is_locked(uuid)

    @method()
    def get_version(self, vault, uuid):
        """Return a version from a vault.

        The latest version identified by *uuid* is returned from *vault*.  The
        version is returned as a dictionary. If the version does not exist,
        ``None`` is returned.
        
        In Bluepass, vaults contain versions. Think of a version as an
        arbitrary object that is versioned and encrypted. A version has at
        least "id" and "_type" keys. The "id" will stay constant over the
        entire lifetime of the version. Newer versions supersede older
        versions. This method call returns the newest instance of the version.

        Versions are the unit of synchronization in our peer to peer
        replication protocol. They are also the unit of encryption. Both
        passwords are groups are stored as versions.
        """
        return instance(Model).get_version(vault, uuid)

    @method()
    def get_versions(self, vault):
        """Return the newest instances for all versions in a vault.

        The return value is a list of dictionaries.
        """
        return instance(Model).get_versions(vault)

    @method()
    def add_version(self, vault, version):
        """Add a new version to a vault.

        The *version* parameter must be a dictionary. The version is a new
        version and should not contain and "id" key yet.
        """
        return instance(Model).add_version(vault, version)

    @method()
    def update_version(self, vault, version):
        """Update an existing version.

        The *version* parameter should be a dictionary. It must have an "id"
        of a version that already exists. The version will become the latest
        version of the specific id.
        """
        return instance(Model).update_version(vault, version)

    @method()
    def delete_version(self, vault, version):
        """Delete a version from a vault.

        This create a special updated version of the record with a "deleted"
        flag set. By default, deleted versions do not show up in the output of
        :meth:`get_versions`.
        """
        return instance(Model).delete_version(vault, version)

    @method()
    def get_version_history(self, vault, uuid):
        """Get the history of a version.

        This returns a ordered list with the linear history all the way from
        the current newest instance of the version, back to the first version.
        """
        return instance(Model).get_version_history(vault, uuid)

    # Password methods

    @method()
    def generate_password(self, method, *args):
        """Generate a password.

        The *method* specifies the method. It can currently be "diceware" or
        "random". The "diceware" method takes one argument: an integer with the
        number of words to generate. The "random" method takes two arguments:
        th size in character, and an alphabest in the form of a regular
        expression character set (e.g. [a-zA-Z0-9]).
        """
        return instance(PasswordGenerator).generate(method, *args)

    @method()
    def password_strength(self, method, *args):
        """Return the strength of a password that was generated by
        :meth:`generate_password`.

        The return value is an integer indicating the entropy of the password
        in bits.
        """
        return instance(PasswordGenerator).strength(method, *args)

    # Locator methods

    @method()
    def locator_is_available(self):
        """Return whether or not the locator is available.

        There are platforms where we don't have a locator at the moment.
        """
        locator = instance(Locator)
        return len(locator.sources) > 0

    @method()
    def get_neighbors(self):
        """Return current neighbords on the network.

        The return value is a list of dictionaries.
        """
        return instance(Locator).get_neighbors()

    # Pairing methods

    @method()
    def set_allow_pairing(self, timeout):
        """Be visible on the network for *timeout* seconds.

        When visible, other instances of Bluepass will be able to find us, and
        initiate a pairing request. The pairing request will still have to be
        approved, and PIN codes needs to be exchanged.
        """
        publisher = instance(SyncAPIPublisher)
        publisher.set_allow_pairing(timeout)

    @method()
    def pair_neighbor_step1(self, node, source):
        """Start a new pairing process.

        A pairing process is started with node *node* residing in source
        *source*.

        The return value is a string containing a random cookie that identifies
        the current request.
        """
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
        cookie = binascii.hexlify(self.crypto.random(16)).decode('ascii')
        self.send_response(cookie)
        name = util.gethostname()
        for addr in neighbor['addresses']:
            client = SyncAPIClient()
            addr = addr['addr']
            try:
                client.connect(addr)
            except SyncAPIError as e:
                continue  # try next address
            try:
                kxid = client.pair_step1(vault, name)
            except SyncAPIError as e:
                status = e.args[0]
                detail = e.asdict()
            else:
                status = 'OK'
                detail = {}
                self.pairdata[cookie] = (kxid, neighbor, addr)
            self.send_notification('PairNeighborStep1Completed', cookie, status, detail)
            client.close()
            break

    @method()
    def pair_neighbor_step2(self, cookie, pin, name, password):
        """Complete a pairing process.

        The *cookie* argument are returned by :meth:`pair_neighbor_step1`. The
        *pin* argument is the PIN code that the remote Bluepass instance showed
        to its user. The *name* and *password* arguments specify the name and
        password of the paired vault that is created in the local instance.

        Paired vaults will automatically be kept up to date. Changes made in a
        paired vault in once Bluepass instance will automatically be synced to
        other instances by the Bluepass backend.

        To get notified of new versions that were added, listen for the
        ``VersionsAdded`` signal.
        """
        if cookie not in self.pairdata:
            raise PairingError('NotFound', 'No such key exchange ID')
        kxid, neighbor, addr = self.pairdata.pop(cookie)
        # Again don't keep the GUI blocked while we pair and do a full sync
        self.send_response(None)
        model = instance(Model)
        vault = model.create_vault(name, password, neighbor['vault'],
                                   notify=False)
        certinfo = { 'node': vault['node'], 'name': util.gethostname() }
        keys = certinfo['keys'] = {}
        for key in vault['keys']:
            keys[key] = { 'key': vault['keys'][key]['public'],
                          'keytype': vault['keys'][key]['keytype'] }
        client = SyncAPIClient()
        client.connect(addr)
        try:
            peercert = client.pair_step2(vault['id'], kxid, pin, certinfo)
        except SyncAPIError as e:
            status = e.args[0]
            detail = e.asdict()
            model.delete_vault(vault)
        else:
            status = 'OK'
            detail = {}
            model.add_certificate(vault['id'], peercert)
            client.sync(vault['id'], model, notify=False)
            model.raise_event('VaultAdded', vault)
        self.send_notification('PairNeighborStep2Completed', cookie, status,
                               detail)
        client.close()


class SocketAPIServer(JsonRpcServer):

    def __init__(self):
        super(SocketAPIServer, self).__init__(SocketAPIHandler(), _trace=True)
        instance(Model).add_callback(self._forward_events)
        instance(Locator).add_callback(self._forward_events)
        instance(SyncAPIPublisher).add_callback(self._forward_events)

    def _forward_events(self, event, *args):
        # Forward the event over the message bus.
        for client in self.clients:
            message = jsonrpc.create_notification(event, args)
            self.send_message(client, message)

