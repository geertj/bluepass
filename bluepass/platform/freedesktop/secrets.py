#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import time
import tdbus
import logging

from bluepass.keyring import Keyring, KeyringError
from bluepass.crypto import CryptoProvider, CryptoError, dhparams


CONN_SERVICE = 'org.freedesktop.secrets'
PATH_SERVICE = '/org/freedesktop/secrets'
PATH_LOGIN_COLLECTION = '/org/freedesktop/secrets/collection/login'
IFACE_SERVICE = 'org.freedesktop.Secret.Service'
IFACE_COLLECTION = 'org.freedesktop.Secret.Collection'
IFACE_ITEM = 'org.freedesktop.Secret.Item'
IFACE_SESSION = 'org.freedesktop.Secret.Session'
IFACE_PROPS = 'org.freedesktop.DBus.Properties'


class SecretsKeyring(Keyring):
    """A Keyring interface into the freedesktop "secrets" service.

    This interface is available on Freedesktop platforms (GNOME, KDE).
    """

    def __init__(self, connection):
        """Create a new keyring. Requires a python-tdbus dispatcher as an argument."""
        self.connection = connection
        self.logger = logging.getLogger('bluepass.platform.freedesktop.keyring')
        self.crypto = CryptoProvider()

    def _call_svc(self, path, method, interface, format=None, args=None):
        """INTERNAL: call into the secrets service."""
        try:
            result = self.connection.call_method(path, method, interface=interface,
                            format=format, args=args, destination=CONN_SERVICE)
        except tdbus.Error as e:
            raise KeyringError('D-BUS error for method "%s": %s' % (method, str(e)))
        return result

    def isavailable(self):
        """Return whether or not we can store a key. This requires the secrets
        service to be available and the login keyring to be unlocked."""
        try:
            reply = self._call_svc(PATH_LOGIN_COLLECTION, 'Get', IFACE_PROPS,
                                   'ss', (IFACE_COLLECTION, 'Locked'))
        except KeyringError:
            self.logger.debug('could not access secrets service')
            return False
        value = reply.get_args()[0]
        if value[0] != 'b':
            raise KeyringError('expecting type "b" for "Locked" property')
        self.logger.debug('login keyring is locked: %s', value[1])
        return not value[1]

    def _open_session(self):
        """INTERNAL: open a session."""
        algo = 'dh-ietf1024-sha256-aes128-cbc-pkcs7'
        params = dhparams['ietf1024']
        keypair = self.crypto.dh_genkey(params)
        reply = self._call_svc(PATH_SERVICE, 'OpenSession', IFACE_SERVICE,
                               'sv', (algo, ('ay', keypair[1])))
        if reply.get_signature() != 'vo':
            raise KeyringError('expecting "vo" reply signature for "OpenSession"')
        output, path = reply.get_args()
        if output[0] != 'ay':
            raise KeyringError('expecting "ay" type for output argument of "OpenSession"')
        pubkey = output[1]
        if not self.crypto.dh_checkkey(params, pubkey):
            raise KeyringError('insecure public key returned by "OpenSession"')
        secret = self.crypto.dh_compute(params, keypair[0], pubkey)
        symkey = self.crypto.hkdf(secret, None, '', 16, 'sha256')
        return path, symkey

    def store(self, key, value):
        """Store a secret in the keyring."""
        session, symkey = self._open_session()
        try:
            attrib = { 'application': 'bluepass', 'bluepass-key-id': key }
            props = { 'org.freedesktop.Secret.Item.Label': ('s', 'Bluepass Key: %s' % key),
                      'org.freedesktop.Secret.Item.Attributes': ('a{ss}', attrib) }
            iv = self.crypto.random(16)
            encrypted = self.crypto.aes_encrypt(value, symkey, iv, 'cbc-pkcs7')
            secret = (session, iv, encrypted, 'text/plain')
            reply = self._call_svc(PATH_LOGIN_COLLECTION, 'CreateItem', IFACE_COLLECTION,
                                   'a{sv}(oayays)b', (props, secret, True))
            item, prompt = reply.get_args()
            if item == '/':
                raise KeyringError('not expecting a prompt for "CreateItem"')
            return item
        finally:
            self._call_svc(session, 'Close', IFACE_SESSION)

    def retrieve(self, key):
        """Retrieve a secret from the keyring."""
        session, symkey = self._open_session()
        try:
            attrib = { 'application': 'bluepass', 'bluepass-key-id': key }
            reply = self._call_svc(PATH_LOGIN_COLLECTION, 'SearchItems', IFACE_COLLECTION,
                                   'a{ss}', (attrib,))
            paths = reply.get_args()[0]
            if len(paths) > 1:
                self.logger.error('SearchItems returned %d entries for key "%s"' % (len(paths), key))
                return
            elif len(paths) == 0:
                return
            item = paths[0]
            reply = self._call_svc(item, 'GetSecret', IFACE_ITEM, 'o', (session,))
            secret = reply.get_args()[0]
            decrypted = self.crypto.aes_decrypt(secret[2], symkey, secret[1], 'cbc-pkcs7')
            return decrypted
        finally:
            self._call_svc(session, 'Close', IFACE_SESSION)
