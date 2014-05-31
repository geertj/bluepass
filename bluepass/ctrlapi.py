#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# secret 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import gruvi
from gruvi import jsonrpc, switchpoint
from gruvi.jsonrpc import JsonRpcServer

from . import util, json, crypto, errors
from .factory import *
from .errors import AuthenticationFailed
from .model import *
from .locator import *
from .passwords import *
from .syncapi import *
from .rpckit import RpcHandler, RpcError, route
from ._version import version_info


class ControlApiHandler(RpcHandler):
    """Control API.

    This handler implements the Bluepass control API. The control API is a
    full-functionality JSON-RPC API that is used by "fat" clients like the Qt
    frontend.
    """

    def __init__(self, model=None, locator=None, publisher=None, backend=None):
        super(ControlApiHandler, self).__init__()
        self._model = model or instance(Model)
        self._locator = locator or instance(Locator)
        self._publisher = publisher or instance(SyncApiPublisher)
        from bluepass.backend import Backend
        self._backend = backend or instance(Backend)
        self._pairings = {}

    def pre_request_hook(self, method, *args):
        # This hook is used to authenticate the request.
        authenticated = self.data.get('authenticated', False)
        if not authenticated and method != 'login':
            raise RpcError('Not authenticated')

    def uncaught_exception(self, exc):
        info = errors.get_error_info(exc)
        if not info:
            return
        detail = {'error_name': info.name}
        detail.update(info.detail)
        raise RpcError(info.code, info.name, detail)

    # General

    @route('login', args='[str@>=16]')
    def login(self, tokenid):
        """Login to the control API.

        The *tokenid* argument must be the ID of a valid authentication token.
        """
        token = self._model.get_token(tokenid)
        if token is None:
            raise AuthenticationFailed
        expires = token.get('expires')
        if expires and expires > time.time():
            raise AuthenticationFailed
        allow = token.get('allow', {})
        if not allow.get('control_api'):
            raise AuthenticationFailed
        self.data['authenticated'] = True
        # XXX: revise this
        self.protocol._ctrlapi_authenticated = True
        return True

    @route(args='[]')
    def stop(self):
        """Stop the backend."""
        self._backend.stop()

    @route(args='[]')
    def get_version_info(self):
        """Get versionsecret information.

        The return value is a dictionary containing various versionsecret related
        fields.
        """
        return version_info

    # Configuration

    @route(args='[{...}]')
    def create_config(self, config):
        """Create a new configuration document.
        
        The *config* argument must be a dictionary containing at least a
        "name" key. The name must be unique across all configuration documents.
        """
        return self._model.create_config(config)

    @route(args='[str]')
    def get_config(self, name):
        """Return a configuration document.

        Return the configuration document with name *name* as a Python
        dicarionaty, or ``None`` if the document does not exist.
        """
        return self._model.get_config(name)

    @route(args='[{...}]')
    def update_config(self, name, config):
        """Update a configuration object."""
        return self._model.update_config(name, config)

    # Vaults

    @route(args='[{...}]')
    def create_vault(self, template):
        """Create a new vault.

        The vault's name will be *name*, and its private keys will be encrypted
        with *password*. The vault will start unlocked.

        Vault creation is asynchronous. This method will start the process in
        the background and return immediately with the vault's uuid.  When the
        vault's creation is complete, a "VaultCreationComplete" notification is
        sent with arguments (uuid, success, message).
        """
        uuid = crypto.random_uuid()
        template['id'] = uuid
        def complete_create_vault(send_notification):
            try:
                vault = self._model.create_vault(template)
            except Exception as e:
                self._log.error(str(e))
                success = False
                info = errors.get_error_info(e)
                message = info.message if info is not None else ''
            else:
                success = True
                message = 'vault created successfully'
            send_notification('VaultCreationComplete', uuid, success, message)
        # Pass reference to send_notification because self.protocol is fiber-local
        gruvi.spawn(complete_create_vault, self.protocol.send_notification)
        return uuid

    @route(args='[uuid]')
    def get_vault(self, uuid):
        """Return the vault *uuid*, or null if it doesn't exist."""
        return self._model.get_vault(uuid)

    @route(args='[]')
    def get_vaults(self):
        """Return a list of all vaults.

        This returns both locked and unlocked vaults. To know the status of an
        individual vault, use :meth:`get_vault_status`.
        """
        return self._model.get_vaults()

    @route(args='[uuid]')
    def get_vault_status(self, uuid):
        """Return the status of the vault with ID *uuid*.

        The status will be either ``'LOCKED'`` or ``'UNLOCKED'``.
        """
        return self._model.get_vault_status(uuid)

    @route(args='[{...}]')
    def update_vault(self, uuid, update):
        """Update the vault with ID *uuid*.

        The *update* argument specifies the update to apply. Currently only the
        *name* and *password* attributes can be updated.

        Return the updated vault.
        """
        return self._model.update_vault(uuid, update)

    @route(args='[uuid]')
    def delete_vault(self, uuid):
        """Delete a vault with ID *uuid*.

        All items in the vault will be deleted. This action in irreversible.
        """
        self._model.delete_vault(uuid)

    @route(args='[uuid]')
    def get_vault_statistics(self, uuid):
        """Return statistics about a vault.

        The return value is a dictionary.
        """
        return self._model.get_vault_statistics(uuid)

    @route(args='[uuid, str, *[]]')
    def unlock_vault(self, uuid, password, cache_fields=[]):
        """Unlock a vault.

        The vault with ID *uuid* is unlocked using *password*. An exception is
        raised if the vault does not exist or if the password is incorrect.
        
        Unlockign a vault decrypts the private keys that are stored in the
        store and stores them in memory. After a vault has been unlocked, its
        secrets can be read and updated using :meth:`get_secret` and related
        methods.

        It is OK to unlock a vault that is already unlocked.
        """
        return self._model.unlock_vault(uuid, password, cache_fields)

    @route(args='[uuid]')
    def lock_vault(self, uuid):
        """Lock a vault.

        This destroys the decrypted private keys and any decrypted items
        that are cached.

        It is not an error to lock a vault that is already locked.
        """
        return self._model.lock_vault(uuid)

    # Secrets

    @route(args='[uuid, uuid]')
    def get_secret(self, vault, uuid):
        """Return a secret from a vault.

        Search the vault with ID *vault* for a secret with ID *uuid*. If found,
        the latest version if the secret is returned as a Python dict. If the
        vault does not exist, an exception is raised. If the secret does not
        exist, ``None`` is returned.
        """
        return self._model.get_secret(vault, uuid)

    @route(args='[uuid]')
    def get_secrets(self, vault):
        """Return all secrets from a vault.

        This returns a list containing the latest version for each secret in
        the vault with ID *vault*.
        """
        return self._model.get_secrets(vault)

    @route(args='[uuid, {...}]')
    def create_secret(self, vault, template):
        """Add a new secret to a vault.

        The *secret* parameter must be a dictionary. The secret is a new
        secret and should not contain and "id" key yet.
        """
        return self._model.create_secret(vault, template)

    @route(args='[uuid, uuid, {...}]')
    def update_secret(self, vault, uuid, update):
        """Update an existing secret.

        The *secret* parameter should be a dictionary. It must have an "id"
        of a secret that already exists. The secret will become the latest
        secret of the specific id.
        """
        return self._model.update_secret(vault, uuid, update)

    @route(args='[uuid, uuid]')
    def delete_secret(self, vault, uuid):
        """Delete a secret from a vault.

        This create a special updated secret of the record with a "deleted"
        flag set. By default, deleted secrets do not show up in the output of
        :meth:`get_secrets`.
        """
        return self._model.delete_secret(vault, uuid)

    @route(args='[uuid, uuid, *bool]')
    def get_secret_history(self, vault, uuid, full=False):
        """Get the history of a secret.

        This returns a ordered list with the linear history all the way from
        the current newest instance of the secret, back to the first secret.
        """
        return self._model.get_secret_history(vault, uuid, full)

    # Password methods

    @route(args='[str, ...]')
    def generate_password(self, method, *args):
        """Generate a password.

        The *method* specifies the method. It can currently be "diceware" or
        "random". The "diceware" method takes one argument: an integer with the
        number of words to generate. The "random" method takes two arguments:
        th size in character, and an alphabest in the form of a regular
        expression character set (e.g. [a-zA-Z0-9]).
        """
        return instance(PasswordGenerator).generate(method, *args)

    @route(args='[str, ...]')
    def password_strength(self, method, *args):
        """Return the strength of a password that was generated by
        :meth:`generate_password`.

        The return value is an integer indicating the entropy of the password
        in bits.
        """
        return instance(PasswordGenerator).strength(method, *args)

    # Locator methods

    @route(args='[]')
    def locator_is_available(self):
        """Return whether or not the locator is available.

        There are platforms where we don't have a locator at the moment.
        """
        locator = instance(Locator)
        return len(locator.sources) > 0

    @route(args='[]')
    def get_neighbors(self):
        """Return current neighbords on the network.

        The return value is a list of dictionaries.
        """
        return instance(Locator).get_neighbors()

    # Pairing methods

    @route(args='[int]')
    def set_allow_pairing(self, timeout):
        """Be visible on the network for *timeout* seconds.

        When visible, other instances of Bluepass will be able to find us, and
        initiate a pairing request. The pairing request will still have to be
        approved, and PIN codes needs to be exchanged.
        """
        self._publisher.set_allow_pairing(timeout)

    @route(args='[uuid, str]')
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
        def complete_pair_neighbor_step1(send_notification):
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
                    success = False
                    info = errors.get_error_info(e)
                    message = info.message if info is not None else ''
                else:
                    success = True
                    message = 'OK'
                send_notification('PairNeighborStep1Completed', cookie, success, message)
                client.close()
                break
        gruvi.spawn(complete_pair_neighbor_step1, self.protocol.send_notification)
        return cookie

    @route(args='[str, str, str, str]')
    def pair_neighbor_step2(self, cookie, pin, name, password):
        """Complete a pairing process.

        The *cookie* argument are returned by :meth:`pair_neighbor_step1`. The
        *pin* argument is the PIN code that the remote Bluepass instance showed
        to its user. The *name* and *password* arguments specify the name and
        password of the paired vault that is created in the local instance.

        Paired vaults will automatically be kept up to date. Changes made in a
        paired vault in once Bluepass instance will automatically be synced to
        other instances by the Bluepass backend.

        To get notified of new secrets that were added, listen for the
        ``VersionsAdded`` signal.
        """
        if cookie not in self._pairings:
            raise NotFound('No such key exchange ID')
        kxid, neighbor, addr = self._pairings.pop(cookie)
        def complete_pair_neighbor_step2(send_notification):
            template = {'id': neighbor['vault'], 'name': name, 'password': password}
            vault = self._model.create_vault(template)
            certinfo = {'node': vault['node'], 'name': util.gethostname()}
            certinfo['keys'] = self._model.get_public_keys(vault['id'])
            client = SyncApiClient()
            client.connect(addr)
            try:
                peercert = client.pair_step2(vault['id'], kxid, pin, certinfo)
                self._model.create_certificate(vault['id'], peercert)
            except Exception as e:
                self._log.exception('exception in step #2 of pairing')
                success = False
                info = errors.get_error_info(e)
                message = info.message if info else ''
                self._model.delete_vault(vault['id'])
            else:
                success = True
                message = 'OK'
                try:
                    client.sync(vault['id'], self._model)
                except SyncApiError:
                    pass
                self._model.raise_event('VaultAdded', vault)
            send_notification('PairNeighborStep2Completed', cookie, success, message)
            client.close()
        gruvi.spawn(complete_pair_neighbor_step2, self.protocol.send_notification)


class ControlApiServer(JsonRpcServer):

    def __init__(self, **kwargs):
        handler = ControlApiHandler(**kwargs)
        super(ControlApiServer, self).__init__(handler)
        handler._model.add_callback(self._forward_events)
        handler._locator.add_callback(self._forward_events)
        handler._publisher.add_callback(self._forward_events)

    def _forward_events(self, event, *args):
        # Forward an event as a notification over the message bus
        for _, protocol in self.connections:
            message = jsonrpc.create_notification(event, args)
            protocol.send_message(message)
