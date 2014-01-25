#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import gruvi
from gruvi import jsonrpc, switchpoint
from gruvi.jsonrpc import JsonRpcServer

from . import util, json, crypto
from .factory import *
from .errors import *
from .model import *
from .locator import *
from .passwords import *
from .syncapi import *
from .jsonrpc import *
from ._version import version_info


# These exceptions are passed through to API consumers as JSON-RPC error
# responses. List them from general to specific (the last match is used).

_errors = [(AuthenticationFailed, jsonrpc.SERVER_ERROR-1),
    (ValidationError, jsonrpc.SERVER_ERROR-2),
    (NotFound, jsonrpc.SERVER_ERROR-3),
    (ModelError, jsonrpc.SERVER_ERROR-20),
    (VaultLocked, jsonrpc.SERVER_ERROR-21),
    (InvalidPassword, jsonrpc.SERVER_ERROR-22),
    (LocationError, jsonrpc.SERVER_ERROR-30),
    (SyncApiError, jsonrpc.SERVER_ERROR-40)]


class ControlApiHandler(JsonRpcHandler):
    """The JSON-RPC control API."""

    def __init__(self, model=None, locator=None, publisher=None, backend=None):
        super(ControlApiHandler, self).__init__()
        self._model = model or instance(Model)
        self._locator = locator or instance(Locator)
        self._publisher = publisher or instance(SyncApiPublisher)
        from bluepass.backend import Backend
        self._backend = backend or instance(Backend)
        self._pairings = {}

    @property
    def model(self):
        return self._model

    @property
    def locator(self):
        return self._locator

    @property
    def publisher(self):
        return self._publisher

    @property
    def backend(self):
        return self._backend

    def authenticate(self):
        """Authenticate this request."""
        return getattr(self.transport, '_ctrlapi_authenticated', False)

    def create_error(self, message, exc):
        """Create an error reply for *message* based on exception *exc*."""
        if message.get('id') is None:
            self._log.exception('uncaught exception in notification handler')
            return
        last_match = None
        for tup in _errors:
            if isinstance(exc, tup[0]):
                last_match = tup
        if last_match is None:
            self._log.exception('uncaught exception in method handler')
            return jsonrpc.create_error(message, jsonrpc.SERVER_ERROR)
        message = exc.args[0] if exc.args else exc.__doc__
        return jsonrpc.create_error(last_match[1], message)

    # General

    @method('[str@>=16]')
    @anonymous
    def login(self, cookie):
        token = self.model.get_token(cookie)
        if token is None:
            return False
        expires = token.get('expires')
        if expires and expires > time.time():
            return False
        rights = token.get('rights', {})
        if not rights.get('control_api'):
            return False
        self.transport._ctrlapi_authenticated = True
        return True

    @method('[]')
    def stop(self):
        self.backend.stop()

    @method('[]')
    def get_version_info(self):
        """Get version information.

        The return value is a dictionary with at least the "version" key in it.
        """
        return {'version': version_info['version']}

    # Configuration

    @method('[{...}]')
    def create_config(self, config):
        """Create a new configuration document."""
        return self.model.create_config(config)

    @method('[str]')
    def get_config(self, name):
        """Return the configuration object.

        The configuration object is a dictionary that can be used by frontends
        to store configuration data.
        """
        return self.model.get_config(name)

    @method('[{...}]')
    def update_config(self, config):
        """Update the configuration object."""
        return self.model.update_config(config)

    # Vaults

    @method('[str, str]')
    def create_vault(self, name, password):
        """Create a new vault.

        The vault will have the name *name*. The vault's private keys will be
        encrypted with *password*.

        Vault creation is asynchronous. This method will return the vault UUID.
        When the vault creation is done, a "VaultCreationComplete" notification
        is sent.
        """
        uuid = crypto.random_uuid()
        def complete_create_vault(message, protocol, transport):
            try:
                vault = self.model.create_vault(name, password, uuid)
            except Exception as e:
                status = False
                detail = self.create_error(message, e) or {}
                if not detail:
                    self._log.exception('uncaught exception when creating vault')
            else:
                status = True
                detail = vault
            protocol.send_notification(transport, 'VaultCreationComplete', uuid, status, detail)
        gruvi.spawn(complete_create_vault, self.message, self.protocol, self.transport)
        return uuid

    @method('[uuid]')
    def get_vault(self, uuid):
        """Return the vault *uuid*, or null if it doesn't exist."""
        return self.model.get_vault(uuid)

    @method('[]')
    def get_vaults(self):
        """Return an array of all vaults."""
        return self.model.get_vaults()

    @method('[{...}]')
    def update_vault(self, uuid, update):
        """Update a vault.

        The vault *uuid* is updated with attributes from the object *vault*.
        Only the *name* and *password* attributes can be updated.
        """
        return self.model.update_vault(uuid, update)

    @method('[uuid]')
    def delete_vault(self, uuid):
        """Delete a vault.

        This also deletes all items in the vault.
        """
        self.model.delete_vault(uuid)

    @method('[uuid]')
    def get_vault_statistics(self, uuid):
        """Return statistics about a vault.

        The return value is a dictionary.
        """
        return self.model.get_vault_statistics(uuid)

    @method('[uuid, str]')
    def unlock_vault(self, uuid, password):
        """Unlock a vault.

        The vault *uuid* is unlocked using *password*. This decrypts the
        private keys that are stored in the database and stored them in
        memory.

        It is not an error to unlock a vault that is already unlocked.
        """
        return self.model.unlock_vault(uuid, password)

    @method('[uuid]')
    def lock_vault(self, uuid):
        """Lock a vault.

        This destroys the decrypted private keys and any decrypted items
        that are cached.

        It is not an error to lock a vault that is already locked.
        """
        return self.model.lock_vault(uuid)

    @method('[uuid]')
    def vault_is_locked(self, uuid):
        """Return whether or not the vault *uuid* is locked."""
        return self.model.vault_is_locked(uuid)

    # Versions

    @method('[uuid, uuid]')
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
        return self.model.get_version(vault, uuid)

    @method('[uuid]')
    def get_versions(self, vault):
        """Return the newest instances for all versions in a vault.

        The return value is a list of dictionaries.
        """
        return self.model.get_versions(vault)

    @method('[uuid, {...}]')
    def add_version(self, vault, version):
        """Add a new version to a vault.

        The *version* parameter must be a dictionary. The version is a new
        version and should not contain and "id" key yet.
        """
        return self.model.add_version(vault, version)

    @method('[uuid, {...}]')
    def replace_version(self, vault, version):
        """Update an existing version.

        The *version* parameter should be a dictionary. It must have an "id"
        of a version that already exists. The version will become the latest
        version of the specific id.
        """
        return self.model.replace_version(vault, version)

    @method('[uuid, {...}]')
    def delete_version(self, vault, version):
        """Delete a version from a vault.

        This create a special updated version of the record with a "deleted"
        flag set. By default, deleted versions do not show up in the output of
        :meth:`get_versions`.
        """
        return self.model.delete_version(vault, version)

    @method('[uuid, uuid]')
    def get_version_history(self, vault, uuid):
        """Get the history of a version.

        This returns a ordered list with the linear history all the way from
        the current newest instance of the version, back to the first version.
        """
        return self.model.get_version_history(vault, uuid)

    # Password methods

    @method('[str, ...]')
    def generate_password(self, method, *args):
        """Generate a password.

        The *method* specifies the method. It can currently be "diceware" or
        "random". The "diceware" method takes one argument: an integer with the
        number of words to generate. The "random" method takes two arguments:
        th size in character, and an alphabest in the form of a regular
        expression character set (e.g. [a-zA-Z0-9]).
        """
        return instance(PasswordGenerator).generate(method, *args)

    @method('[str, ...]')
    def password_strength(self, method, *args):
        """Return the strength of a password that was generated by
        :meth:`generate_password`.

        The return value is an integer indicating the entropy of the password
        in bits.
        """
        return instance(PasswordGenerator).strength(method, *args)

    # Locator methods

    @method('[]')
    def locator_is_available(self):
        """Return whether or not the locator is available.

        There are platforms where we don't have a locator at the moment.
        """
        locator = instance(Locator)
        return len(locator.sources) > 0

    @method('[]')
    def get_neighbors(self):
        """Return current neighbords on the network.

        The return value is a list of dictionaries.
        """
        return instance(Locator).get_neighbors()

    # Pairing methods

    @method('[int]')
    def set_allow_pairing(self, timeout):
        """Be visible on the network for *timeout* seconds.

        When visible, other instances of Bluepass will be able to find us, and
        initiate a pairing request. The pairing request will still have to be
        approved, and PIN codes needs to be exchanged.
        """
        self.publisher.set_allow_pairing(timeout)

    @method('[uuid, str]')
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
            raise NotFound('No such neighbor: {0}/{1}'.format(source, node))
        visible = neighbor['properties'].get('visible')
        if not visible:
            raise PairingError('Node is not visible')
        vault = neighbor['vault']
        model = instance(Model)
        if model.get_vault(vault):
            raise PairingError('Vault already exists: {0}'.format(vault))
        cookie = crypto.random_cookie()
        def complete_pair_neighbor_step1(message, protocol, transport):
            name = util.gethostname()
            for addr in neighbor['addresses']:
                client = SyncApiClient()
                addr = addr['addr']
                try:
                    client.connect(addr)
                except SyncApiError as e:
                    continue  # try next address
                try:
                    kxid = client.pair_step1(vault, name)
                    self._pairings[cookie] = (kxid, neighbor, addr)
                except Exception as e:
                    self._log.exception('exception in step #1 of pairing')
                    status = False
                    detail = self.create_error(message, e) or {}
                else:
                    status = True
                    detail = {}
                protocol.send_notification(transport, 'PairNeighborStep1Completed',
                                           cookie, status, detail)
                client.close()
                break
        gruvi.spawn(complete_pair_neighbor_step1, self.message, self.protocol, self.transport)
        return cookie

    @method('[str, str, str, str]')
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
        if cookie not in self._pairings:
            raise NotFound('No such key exchange ID')
        kxid, neighbor, addr = self._pairings.pop(cookie)
        def complete_pair_neighbor_step2(message, protocol, transport):
            vault = self.model.create_vault(name, password, neighbor['vault'], notify=False)
            certinfo = {'node': vault['node'], 'name': util.gethostname()}
            vault = self.model.vaults[vault['id']]  # access "keys"
            keys = certinfo['keys'] = {}
            for key in vault['keys']:
                keys[key] = {'key': vault['keys'][key]['public'],
                             'keytype': vault['keys'][key]['keytype']}
            certinfo['restrictions'] = {}
            client = SyncApiClient()
            client.connect(addr)
            try:
                peercert = client.pair_step2(vault['id'], kxid, pin, certinfo)
                self.model.add_certificate(vault['id'], peercert)
            except Exception as e:
                self._log.exception('exception in step #2 of pairing')
                status = False
                detail = self.create_error(message, e) or {}
                model.delete_vault(vault)
            else:
                status = True
                detail = {}
                try:
                    client.sync(vault['id'], self.model, notify=False)
                except SyncApiError:
                    pass
                self.model.raise_event('VaultAdded', vault)
            protocol.send_notification(transport, 'PairNeighborStep2Completed',
                                       cookie, status, detail)
            client.close()
        gruvi.spawn(complete_pair_neighbor_step2, self.message, self.protocol, self.transport)


class ControlApiServer(JsonRpcServer):

    def __init__(self, **kwargs):
        handler = ControlApiHandler(**kwargs)
        super(ControlApiServer, self).__init__(handler)
        handler.model.add_callback(self._forward_events)
        handler.locator.add_callback(self._forward_events)
        handler.publisher.add_callback(self._forward_events)
        self._tracefile = None

    def _forward_events(self, event, *args):
        # Forward an event as a notification over the message bus
        for client in self.clients:
            message = jsonrpc.create_notification(event, args)
            self.send_message(client, message)

    def set_tracefile(self, tracefile):
        self._tracefile = tracefile

    @switchpoint
    def upcall(self, method, *args):
        for client in self.clients:
            if not client._ctrlapi_authenticated:
                continue
            # XXX: in parallel to all clients. Add timeout
            return self.call_method(client, method, *args)

    def _log_request(self, message):
        if not self._tracefile:
            return
        self._tracefile.write('/* <= incoming {0}, version {1} */\n'.format
                        (jsonrpc.message_type(message), message.get('jsonrpc', '1.0')))
        self._tracefile.write(json.dumps_pretty(message))
        self._tracefile.write('\n\n')
        self._tracefile.flush()

    def _log_response(self, message):
        if not self._tracefile:
            return
        self._tracefile.write('/* => outgoing {0}, version {1} */\n'.format
                        (jsonrpc.message_type(message), message.get('jsonrpc', '1.0')))
        self._tracefile.write(json.dumps_pretty(message))
        self._tracefile.write('\n\n')
        self._tracefile.flush()
