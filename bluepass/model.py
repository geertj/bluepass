#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import time
import itertools
from copy import deepcopy

import six
import pyuv
import gruvi

from . import base64, json, logging, validate, crypto, util
from .errors import *
from .skiplist import *

__all__ = ['Model', 'ModelError', 'VaultLocked', 'InvalidPassword']


class ModelError(Error):
    """Model error."""

class VaultLocked(ModelError):
    """Vault is locked."""

class InvalidPassword(ModelError):
    """Invalid password."""


# Validators for our data model

va_config = validate.compile('{ name: str@>0, ... }')

va_token = validate.compile("""
        { id: str@>=20, expires: float>=0, allow:
            { control_api: *bool, client_api: *bool } }
        """)

va_vault = validate.compile("""
        { id: uuid, name: str@>0@<=100, node: uuid, keys:
            { sign:
                { keytype: str="ed25519", private: b64@>=16, public: b64@>=16, encinfo:
                    *{ algo: str="xsalsa20", nonce: b64@>=16, kdf: str="scrypt",
                       salt: b64@>=16, N: int>0, r: int>0, p: int>0, l: int>0 },
                  pwcheck:
                    *{ algo: str="poly1305", random: b64@>=16, verifier: b64@>=16 } }
              encrypt:
                { keytype: str="curve25519", private: b64@>=16, public: b64@>=16, encinfo:
                    *{ algo: str="xsalsa20", nonce: b64@>=16, kdf: str="scrypt",
                       salt: b64@>=16, N: int>0, r: int>0, p: int>0, l: int>0 },
                  pwcheck:
                    *{ algo: str="poly1305", random: b64@>=16, verifier: b64@>=16 } }
              auth:
                { keytype: str="ed25519", private: b64@>=16, public: b64@>=16 } } }
        """)

va_vault_tmpl = validate.compile('{id: *uuid, name: str@>0@<=100, password: str@<=100}')
va_vault_upd = validate.compile('{name: *str@>0@<=100, password: *str@>0@<=100}')

va_item = validate.compile("""
        { id: uuid, type: str="Item", vault: uuid,
          origin: { node: uuid, seqnr: int>=0 },
          payload: { type: str="Certificate"|="Encrypted", ... }
          signature: { algo: str="ed25519", blob: b64@>=16 } }
        """)

va_cert = validate.compile("""
        { id: uuid, payload:
            {  id: uuid, type:str="Certificate", node: uuid, name: str@>0@<=100, keys:
                { sign: *{ public: b64, keytype: str="ed25519" },
                  encrypt: *{ public: b64, keytype: str="curve25519" },
                  auth: *{ public: b64, keytype: str="ed25519" } } }, ... }
        """)
va_cert_tmpl = validate.compile("""
        { node: uuid, name: str@>0@<=100, keys:
            { sign: *{ public: b64, keytype: str="ed25519" },
              encrypt: *{ public: b64, keytype: str="curve25519" },
              auth: *{ public: b64, keytype: str="ed25519" } } }
        """)


va_enc = validate.compile("""
        { id: uuid, payload:
            { type: str="Encrypted", algo: str="xsalsa20", nonce: b64@>=16,
              blob: b64@>=2, keyalgo: str="curve25519", keykey: b64@>=16, keys: { ... } }, ... }
        """)
# XXX: implement this extra validation
#va_enc.add('/payload/keys/*', '[uuid, b64@>=16]')

va_secret = validate.compile("""
        { id: uuid, payload:
            { id: uuid, type: str="Secret", parent: *uuid, created_at: float>=0,
              deleted: *bool, version: uuid, fields: { ... } }, ... }
        """)
va_secret_tmpl = validate.compile('{ fields: { ... } }')

va_vector = validate.compile('[...]')
# XXX: implement this extra validation
#va_vector.add('/[*]', '[uuid, int>=0]')


# Utility functions

def filter_dict(d, include=None, exclude=None):
    """Filter a dictionary, or a list of dictionaries, in-place.

    If *include* is specified, it must be a sequence and only keys in the
    sequence will be be in the result. If *exclude* is specified, it must be a
    sequence and all keys not in the sequence will be in the result. If neither
    are specified, all keys will be in the result.
    """
    if d is None:
        return
    elif isinstance(d, dict):
        for key in list(d):
            if include is not None and key not in include or \
                    exclude is not None and key in exclude:
                del d[key]
    else:
        raise TypeError('d: expecting dict, got {0.__name_!r}', type(d))


def copy_dict(d, include=None, exclude=None):
    """Like :func:`filter_dict`, but creates a deep copy of the dict."""
    d = deepcopy(d)
    if include or exclude:
        filter_dict(d, include, exclude)
    return d


def update_dict(d, update, include=None, exclude=None):
    """Update dictionary *d* with updates from *update*.

    The *include* and *exclude* parameters have the same meaning as in
    :meth:`filter_dict`.
    """
    for key,value in update.items():
        if include is not None and key not in include or \
                exclude is not None and key in exclude:
            continue
        if key in d:
            if isinstance(d[key], dict) and isinstance(value, dict):
                update_dict(d[key], value)
            elif value is not None:
                d[key] = value
            else:
                del d[key]
        elif value is not None:
            d[key] = value


def abbr(uuid):
    """Abbreviate a UUID."""
    if uuid is None:
        return '(none)'
    elif isinstance(uuid, six.string_types):
        return '{0:.6}..'.format(uuid)
    else:
        return '(invalid)'


class Model(object):
    """This class implements our data model on top of a document store.

    The model contains the following types:

    * config: A simple configuration document that front-ends can use to store
        persistent configuration.
    * token: An access token that grants persistent (or not) rights to access
        one of the APIs.
    * vault: The unit of replication and a container for items. A vault can be
        shared with multiple instances of Bluepass. Each instance is identified
        by a unique node ID. Every node has a unique set of keys for each
        vault: an authentication key, an signing key and an encryption key.
    * item: The elements in a vault. Items have meta data to aid in replication
        (origin node and sequence number), and always have a signature.
        Currently there are two types of items: a certificate  and a secret.
        Certificates are not encrypted while secrets are. Items are never
        changed once created. They are added to a vault in an append-only
        fashion.
    * certificate: A type of item. A certificate binds a node ID to its public
        keys. Each item requires a signature by a public key for which there is
        a trusted certificate chain.
    * secret: A type of item. The item is encrypted, and supports version
        control and confict resolution.
    """

    def __init__(self, store):
        """Create a new model on top of *store*."""
        self._store = store
        self._vaults = {}
        self._next_seqnr = {}
        self._decrypted_keys = {}
        self._trusted_certs = {}
        self._secret_index = {}
        self._secret_cache = {}
        self._cached_fields = {}
        self._linear_history = {}
        self._full_history = {}
        self._callbacks = []
        self._log = logging.get_logger()
        self._check_schema()
        self._load_vaults()
        for vault in self._vaults:
            self._load_certificates(vault)
        self._expire_tokens()

    @property
    def store(self):
        return self._store

    @property
    def callbacks(self):
        return self._callbacks

    def _check_schema(self):
        """Make sure the store schema is up to date."""
        store = self.store
        if 'configs' not in store.collections:
            store.create_collection('configs')
            store.create_index('configs', '$name', 'TEXT', 'UNIQUE')
        if 'tokens' not in store.collections:
            store.create_collection('tokens')
        if 'vaults' not in store.collections:
            store.create_collection('vaults')
        if 'items' not in store.collections:
            store.create_collection('items')
            store.create_index('items', '$vault', 'TEXT')
            store.create_index('items', '$origin$node', 'TEXT')
            store.create_index('items', '$origin$seqnr', 'INT')
            store.create_index('items', '$payload$node', 'TEXT')
            store.create_index('items', '$payload$type', 'TEXT')

    # Load objects 

    def _load_vaults(self):
        """Check and load all vaults."""
        errors = 0
        self._log.info('loading vaults')
        vaults = self.store.findall('vaults')
        for vault in vaults:
            uuid = vault.get('id')
            vres = va_vault.validate(vault)
            if vres.error:
                self._log.error('vault {!r} error: {!r}', abbr(uuid), vres.error)
                errors += 1
                continue
            self._vaults[uuid] = vault
            self._decrypted_keys[uuid] = {}
            key = self._decrypt_vault_key(vault['keys']['auth'], '')
            self._decrypted_keys[uuid]['auth'] = key
            self._secret_index[uuid] = {}
            self._secret_cache[uuid] = SkipList()
            self._cached_fields[uuid] = set()
            self._linear_history[uuid] = {}
            self._full_history[uuid] = {}
            result = self.store.execute("""
                    SELECT MAX($origin$seqnr)
                    FROM items
                    WHERE $origin$node = ? AND $vault = ?
                    """, (vault['node'], vault['id']))
            self._next_seqnr[uuid] = result[0][0] + 1 if result[0][0] else 1
            self._log.debug('loaded vault {!r}', abbr(uuid))
        self._log.info('loaded {} vaults, skipped {}', len(self._vaults), errors)

    def __collect_certs(self, node, nodekey, certs, result):
        """Collect certificates that have a signature chain back to a node."""
        for cert in certs.pop(node, []):
            if not self._verify_signature(cert, nodekey):
                continue
            result.append(cert)
            payload = cert['payload']
            key = payload['keys'].get('sign')
            if not key:
                continue
            subj = payload['node']
            subjkey = base64.decode(key['public'])
            self.__collect_certs(subj, subjkey, certs, result)

    def _load_certificates(self, vault):
        """Load certificates and determine list of trusted nodes."""
        assert vault in self._vaults
        self._log.info('loading certificates for vault {!r}', abbr(vault))
        # Create a mapping of certificates by their signer
        certs = {}
        query = "$vault = ? AND $payload$type = 'Certificate'"
        items = self.store.findall('items', query, (vault,))
        for cert in items:
            vres = va_cert.validate(cert)
            if vres.error:
                self._log.error('cert {!r}: {!r}', cert.get('id'), vres.error)
                continue
            certs.setdefault(cert['origin']['node'], []).append(cert)
        nodes = set((it['payload']['node'] for it in items))
        # Collect valid certs: a valid cert is one that is signed by a trusted
        # signing key. A trusted signing key is our own key, or a key that has
        # a valid certificate with a "sign" key.
        node = self._vaults[vault]['node']
        nodekey = base64.decode(self._vaults[vault]['keys']['sign']['public'])
        result = []
        self.__collect_certs(node, nodekey, certs, result)
        trusted_certs = {}
        for item in result:
            cert = item['payload']
            node = cert['node']
            # Create a single certificate for each node with the union of all
            # the certified keys
            if node not in trusted_certs:
                trusted_certs[node] = cert
            else:
                trusted_certs[node]['keys'].update(cert['keys'])
        self._log.info('vault has {} nodes with valid trust path', len(trusted_certs))
        self._trusted_certs[vault] = trusted_certs

    def _expire_tokens(self):
        """Expire session tokens."""
        # Also delete session tokens (expires = 0)
        now = int(time.time())
        deleted = self.store.delete('tokens', '$expires < ?', (now,))
        self._log.debug('expired {} tokens', deleted)

    # Secret cache and history

    def _sort_history(self, secrets):
        """Find the current version from a set of secrets, and return a list
        with the current version at the front followed by all its ancestors.
        """
        assert len(secrets) > 0
        # Our conflict resulution works like this: the leaf in the tree with
        # the highest created_at time is the current version.
        #
        # Using a time stamp is desirable, because secrets often refer to an
        # external entity like a web site. So the secret with the highest time
        # stamp shold be the current one.
        #
        # The disadvantage of using timestamps is that there could be nodes
        # with wrong clock. This is where the tree comes into play. An child
        # node will always override its parent, even if it the parent has an
        # outrageous timestamp (e.g. years into the future).
        #
        # In the presence of a partition *and* a wrong clock, the item with the
        # highest time stamp will win. Once the nodes are synced again, and the
        # wrong item was selected because of a wrong clock, saving the current
        # node again will fix it.
        #
        # In distributed computing speak, this would be an AP system with
        # eventual consistency.
        #
        # First construct a tree mapping parents to their children. Also create
        # a map from version -> secret.
        secid = secrets[0]['id']
        tree = {}; secbyver = {}
        for secret in secrets:
            parent = secret.get('parent', secret['version'])
            if parent != secret['version']:
                tree.setdefault(parent, []).append(secret)
            secbyver[secret['version']] = secret
        # Find the leaves
        leaves = []
        for secret in secrets:
            version = secret['version']
            if version not in tree:
                leaves.append(secret)
        if len(leaves) == 0:
            # All secrets are in a single cycle. This is a serious error, but
            # can be resolved easily by just taking the most recent secret.
            self._log.error('secret {!r} has cycle in its history', abbr(secid))
            leaves = secrets
        assert len(leaves) > 0
        # Find the leaf with the highest date, and construct back its history.
        leaves.sort(key=lambda s: s['created_at'], reverse=True)
        history = [leaves[0]]
        leaf = current = history[0]
        parent = current.get('parent', current['version'])
        while parent not in (current['version'], leaf['version']):
            current = secbyver[parent]
            history.append(current)
            parent = current.get('parent', current['version'])
        return history
 
    def _update_secret_cache(self, vault, items):
        """Update the secrets index and cache for *items*."""
        # Group items by secret ID (which is immutable across versions).
        # Also keep an index from secret ID back to the item ID.
        grouped = {}
        for item in items:
            secid = item['payload']['id']
            grouped.setdefault(secid, []).append(item)
        # Now per secret, create a linear history using our _sort_history()
        # function, and take the most recent one as the current version.
        changes = []
        isnew = lambda it: it['payload']['version'] not in self._secret_index[vault]
        fields = self._cached_fields[vault]
        for secid,items in grouped.items():
            # Only cache the payload and the fields that were marked as cached
            # when the vault was unlocked.
            secrets = [copy_dict(item['payload']) for item in items if isnew(item)]
            for secret in secrets:
                filter_dict(secret['fields'], include=fields)
            self._full_history[vault].setdefault(secid, []).extend(secrets)
            linear = self._sort_history(self._full_history[vault][secid])
            self._linear_history[vault][secid] = linear
            current = self._secret_cache[vault].search(secid)
            if not current and not linear[0].get('deleted'):
                self._secret_cache[vault].insert(secid, linear[0])
            elif current and linear[0].get('deleted'):
                self._secret_cache[vault].remove(secid)
            elif current and linear[0]['version'] != current['version']:
                self._secret_cache[vault].replace(secid, linear[0])
            else:
                continue
            changes.append(linear[0])
        # Update the mapping from version to item ID. This mapping marks
        # versions we know about, and is also used by get_secret() to load
        # individual secrets from disk.
        for item in items:
            verid = item['payload']['version']
            self._secret_index[vault][verid] = item['id']
        return changes

    def _load_secrets(self, vault):
        """Index all secrets and their history for a vault."""
        errors = 0
        secrets = []
        self._log.info('loading secrets for vault {!r}', abbr(vault))
        query = "$vault = ? AND $payload$type = 'Encrypted'"
        items = self.store.findall('items', query, (vault,))
        for item in items:
            itmid = item.get('id')
            vres = va_enc.validate(item)
            if vres.error:
                self._log.error('item {!r} corrupt in store: {!r}', abbr(itmid),  vres.error)
                errors += 1
                continue
            if not self._verify_item(vault, item) or not self._decrypt_item(vault, item):
                continue
            vres = va_secret.match(item)
            if vres.error:
                self._log.error('secret {!r} corrupt in store: {!r}', abbr(itmid), vres.error)
                errors += 1
                continue
            secrets.append(item)
        self._update_secret_cache(vault, secrets)
        self._log.info('loaded {} secrets, skipped {}', len(secrets), errors)
        # Dump some more stats in the logs
        cursize = len(self._secret_cache[vault])
        linsize = sum((len(h) for h in self._linear_history[vault].values()))
        fullsize = sum((len(h) for h in self._full_history[vault].values()))
        self._log.info('history: current={}, linear={}, full={}', cursize, linsize, fullsize)

    def _readdress_secrets(self, vault):
        """Re-address all secrets in *vault*."""
        errors = 0
        self._log.info('re-addressing all secrets')
        secrets = self._secret_cache[vault]
        with self.store.begin():
            for secid,secret in secrets.items():
                itmid = self._secret_index[vault][secret['version']]
                item = self.store.findone('items', '$id = ?', (itmid,))
                if not va_item.match(item) or not va_enc.match(item):
                    self._log.error('item {!r} corrupt in store', abbr(itmid))
                    errors += 1
                    continue
                if not self._verify_item(vault, item):
                    errors += 1
                    continue
                if not self._decrypt_item(vault, item):
                    errors += 1
                    continue
                # Give the item an new ID and origin so that replication will
                # pick it up. The secret itself stays the same. Nodes that can
                # already decrypt it won't pick it up.
                # XXX: Maybe it is cleaner to create a new version?
                item['id'] = crypto.random_uuid()
                self._encrypt_item(vault, item)
                self._add_origin(vault, item)
                self._sign_item(vault, item)
                self.store.insert('items', item)
        self._log.info('re-addressed {} secrets, skipped {}', len(secrets), errors)

    # Helpers

    def _new_item(self, vault, payload):
        """Create a new empty item."""
        item = {}
        item['id'] = crypto.random_uuid()
        item['type'] = 'Item'
        item['vault'] = vault
        item['payload'] = copy_dict(payload)
        return item

    def _new_certificate(self, vault, cert):
        """Create a new certificate."""
        item = self._new_item(vault, cert)
        payload = item['payload']
        payload['id'] = crypto.random_uuid()
        payload['type'] = 'Certificate'
        return item

    def _new_secret(self, vault, secret, parent=None):
        """Create a new empty secret."""
        item = self._new_item(vault, secret)
        payload = item['payload']
        payload['version'] = crypto.random_uuid()
        payload['type'] = 'Secret'
        payload['created_at'] = time.time()
        if parent:
            payload['id'] = parent['id']
            payload['parent'] = parent['version']
        else:
            payload['id'] = crypto.random_uuid()
        return item

    # Item envelopes

    def _add_origin(self, vault, item):
        """Add the origin section to an item."""
        item['origin'] = origin = {}
        origin['node'] = self._vaults[vault]['node']
        origin['seqnr'] = self._next_seqnr[vault]
        self._next_seqnr[vault] += 1
 
    def _sign_item(self, vault, item):
        """Add a signature to an item."""
        assert vault in self._vaults
        assert vault in self._decrypted_keys
        signature = item['signature'] = {}
        signature['algo'] = 'ed25519'
        message = json.dumps_c14n(item).encode('utf8')
        assert 'sign' in self._decrypted_keys[vault]
        signkey = self._decrypted_keys[vault]['sign']['private']
        blob = crypto.sign(message, signkey)
        signature['blob'] = base64.encode(blob)

    def _verify_signature(self, item, pubkey):
        """Verify a signature for an item.

        This only checks if the singature is correct, not whether the signature
        was created by a trusted node.
        """
        assert va_item.match(item)
        if item['signature']['algo'] != 'ed25519':
            self._log.error('item {!r} unknown sign algo {!r}', abbr(item['id']), algo)
            return False
        blob = item['signature'].pop('blob')
        message = json.dumps_c14n(item).encode('utf8')
        signature = base64.decode(blob)
        valid = crypto.sign_verify(message, signature, pubkey)
        if not valid:
            self._log.error('item {!r} has invalid signature', abbr(item['id']))
            return False
        item['signature']['blob'] = blob
        return True

    def _verify_item(self, vault, item):
        """Verify the signature on an item.

        The signature needs to be correct, and needs to be created by a trusted
        node with the "sign_cert" access right.
        """
        assert vault in self._trusted_certs
        node = item['origin']['node']
        if node not in self._trusted_certs[vault]:
            self._log.warning('item {!r} signed by unknown node {!r}',
                              abbr(item['id']), abbr(node))
            return False
        cert = self._trusted_certs[vault][node]
        key = cert['keys'].get('sign')
        if not key:
            self._log.warning('item {!r} signed by unprivileged node {!r}',
                              abbr(item['id']), abbr(node))
            return False
        pubkey = base64.decode(key['public'])
        return self._verify_signature(item, pubkey)

    def _encrypt_item(self, vault, item):
        """Encrypt the payload of an item."""
        assert vault in self._vaults
        assert vault in self._decrypted_keys
        # The "payload" field is encrypted with the xsalsa20 stream cipher
        # using a freshly generated random key.
        clear = item.pop('payload')
        item['payload'] = payload = {}
        payload['type'] = 'Encrypted'
        algo = payload['algo'] = 'xsalsa20'
        noncebytes = crypto.lookup('stream_NONCEBYTES', algo)
        nonce = crypto.random_bytes(noncebytes)
        payload['nonce'] = base64.encode(nonce)
        keybytes = crypto.lookup('stream_KEYBYTES', algo)
        symkey = crypto.random_bytes(keybytes)
        message = json.dumps(clear).encode('utf8')
        blob = crypto.stream_xor(message, nonce, symkey, algo)
        payload['blob'] = base64.encode(blob)
        # Now encrypt the symmetric key for each node (including ourselves)
        # that will need to decrypt this item.
        # For our choice of algorithms, the assertions below should hold.
        keyalgo = payload['keyalgo'] = 'curve25519'
        privbytes = crypto.lookup('scalarmult_SCALARBYTES', keyalgo)
        assert keybytes == privbytes
        hashalgo = 'sha512'
        hashbytes = crypto.lookup('hash_BYTES', hashalgo)
        assert keybytes <= hashbytes
        # Create a new ECDH public key
        keypriv = crypto.random_bytes(privbytes)
        keypub = crypto.scalarmult_base(keypriv, keyalgo)
        payload['keykey']  = base64.encode(keypub)
        # For each node, create an ECDH shared secret, hash it, and xor that to
        # the symmetric key.
        payload['keys'] = keys = {}
        for node,cert in self._trusted_certs[vault].items():
            key = cert['keys'].get('encrypt')
            if not key:
                continue
            nodepub = base64.decode(key['public'])
            nodeshared = crypto.scalarmult(keypriv, nodepub, keyalgo)
            nodehashed = crypto.hash(nodeshared, hashalgo)[:keybytes]
            enckey = crypto.xor(nodehashed, symkey)
            keys[node] = base64.encode(enckey)

    def _decrypt_item(self, vault, item):
        """Decrypt an encrypted payload."""
        assert vault in self._vaults
        assert vault in self._decrypted_keys
        payload = item['payload']
        algo = 'xsalsa20'
        assert payload['algo'] == algo
        keyalgo = 'curve25519'
        assert payload['keyalgo'] == keyalgo
        node = self._vaults[vault]['node']
        if node not in payload['keys']:
            self._log.warning('item {!r} not encrypted to us', abbr(item['id']))
            return False
        # Recover our encryption key.
        enckey = base64.decode(payload['keys'][node])
        keykey = base64.decode(payload['keykey'])
        privkey = self._decrypted_keys[vault]['encrypt']['private']
        shared = crypto.scalarmult(privkey, keykey, keyalgo)
        hashalgo = 'sha512'
        keylen = crypto.lookup('stream_KEYBYTES', algo)
        hashed = crypto.hash(shared, hashalgo)[:keylen]
        symkey = crypto.xor(hashed, enckey)
        # With the decryption key we can now open the payload blob
        blob = base64.decode(item['payload']['blob'])
        nonce = base64.decode(item['payload']['nonce'])
        clear = crypto.stream_xor(blob, nonce, symkey)
        payload = json.try_loads(clear.decode('utf8'), dict)
        if payload is None:
            self._log.error('item {!r} illegal JSON in payload', item['id'])
            return False
        item['payload'] = payload
        return True

    # Vault keys

    def _create_vault_keys(self):
        """Create the keys for a vault."""
        keys = {}
        # The encrypt key is curve25519
        algo = 'curve25519'
        key = keys['encrypt'] = {}
        key['keytype'] = algo
        keybytes = crypto.lookup('scalarmult_SCALARBYTES', algo)
        key['private'] = privkey = crypto.random_bytes(keybytes)
        key['public'] = crypto.scalarmult_base(privkey, algo)
        # The sign key is ed25519
        algo = 'ed25519'
        key = keys['sign'] = {}
        key['keytype'] = algo
        key['public'], key['private'] = crypto.sign_keypair(algo)
        # The auth key is ed25519 as well
        algo = 'ed25519'
        key = keys['auth'] = {}
        key['keytype'] = algo
        key['public'], key['private'] = crypto.sign_keypair(algo)
        return keys
 
    def _encrypt_vault_key(self, key, password):
        """Encrypt and encode a vault key."""
        enc = {}
        enc['keytype'] = key['keytype']
        # The public key is stored as-is.
        enc['public'] = base64.encode(key['public'])
        if not password:
            enc['private'] = base64.encode(key['private'])
            return enc
        # Encrypt the private key.
        password = password.encode('utf8')
        encinfo = enc['encinfo'] = {}
        algo = encinfo['algo'] = 'xsalsa20'
        noncebytes = crypto.lookup('stream_NONCEBYTES', algo)
        nonce = crypto.random_bytes(noncebytes)
        encinfo['nonce'] = base64.encode(nonce)
        # Generate a key from the password and salt using scrypt.
        encinfo['kdf'] = 'scrypt'
        salt = crypto.random_bytes(16)
        encinfo['salt'] = base64.encode(salt)
        N, r, p = crypto.scrypt_params()
        encinfo['N'], encinfo['r'], encinfo['p'] = N, r, p
        keybytes = crypto.lookup('stream_KEYBYTES', algo)
        encinfo['l'] = keybytes
        symkey = crypto.scrypt(password, salt, N, r, p, keybytes)
        enckey = crypto.stream_xor(key['private'], nonce, symkey)
        enc['private'] = base64.encode(enckey)
        # Store a password verifier as well. It is important that the verifier
        # verifies the *generated* key not the password! This conserves the work
        # factor of the KDF.
        pwcheck = enc['pwcheck'] = {}
        algo = pwcheck['algo'] = 'poly1305'
        random = crypto.random_bytes(16)
        pwcheck['random'] = base64.encode(random)
        verifier = crypto.onetimeauth(random, symkey)
        pwcheck['verifier'] = base64.encode(verifier)
        return enc

    def _decrypt_vault_key(self, key, password):
        """Decrypt and decode vault key."""
        dec = {}
        dec['keytype'] = key['keytype']
        dec['public'] = base64.decode(key['public'])
        # Derive the encryption key from the password
        encinfo = key.get('encinfo')
        if encinfo is None:
            dec['private'] = base64.decode(key['private'])
            return dec
        # Create the symmetric key from the password using the KDF.
        password = password.encode('utf8')
        salt = base64.decode(encinfo['salt'])
        assert encinfo['kdf'] == 'scrypt'
        N, r, p, l = encinfo['N'], encinfo['r'], encinfo['p'], encinfo['l']
        symkey = crypto.scrypt(password, salt, N, r, p, l)
        # Check that the derived key is correct
        pwcheck = key['pwcheck']
        pwcalgo = pwcheck['algo']
        assert pwcalgo == 'poly1305'
        random = base64.decode(pwcheck['random'])
        verifier = base64.decode(pwcheck['verifier'])
        if not crypto.onetimeauth_verify(verifier, random, symkey, pwcalgo):
            raise InvalidPassword('Invalid vault password')
        # Decrypt the private key and store in the copy.
        algo = encinfo['algo']
        assert algo == 'xsalsa20'
        privkey = base64.decode(key['private'])
        nonce = base64.decode(encinfo['nonce'])
        dec['private'] = crypto.stream_xor(privkey, nonce, symkey, algo)
        return dec

    # Events / callbacks

    def add_callback(self, callback):
        """Register a callback that that gets notified of model events."""
        self.callbacks.append(callback)

    def raise_event(self, event, *args):
        """Raise an event to all callbacks."""
        for callback in self.callbacks:
            try:
                callback(event, *args)
            except Exception as e:
                self._log.error('callback raised exception: {}' % str(e))

    # Configurations

    def create_config(self, config):
        """Create a new configuration."""
        vres = va_config.validate(config)
        if vres.error:
            raise ValidationError('invalid config: {0}'.format(vres.error))
        self.store.insert('configs', config)
        return config

    def get_config(self, name):
        """Return the configuration *name*."""
        return self.store.findone('configs', '$name = ?', (name,))

    def get_configs(self):
        """Return all configurations."""
        return self.store.findall('configs')

    def update_config(self, name, update):
        """Update a configuration."""
        config = self.store.findone('configs', '$name = ?', (name,))
        if config is None:
            raise NotFound('no such config {0!r}'.format(name))
        update_dict(config, update)
        vres = va_config.validate(config)
        if vres.error:
            raise ValidationError('invalid update: {0}'.format(vres.error))
        self.store.update('configs', config, '$name = ?', (name,))
        return config

    def delete_config(self, name):
        """Delete a configuration document."""
        config = self.store.findone('configs', '$name = ?', (name,))
        if config is None:
            raise NotFound('no such config: {0!r}'.format(name))
        self.store.delete('configs', '$name = ?', (name,))

    # Tokens

    def create_token(self, token):
        """Create a new authentication token *token*."""
        if 'id' not in token:
            token['id'] = crypto.random_cookie()
        vres = va_token.validate(token)
        if not vres.match:
            raise ValidationError('Invalid token: {0}'.format(vres.error))
        self.store.insert('tokens', token)
        return token

    def get_token(self, tokid):
        """Return the authentication token identified by *tokid*."""
        return self.store.findone('tokens', '$id = ?', (tokid,))

    def get_tokens(self):
        """Return a list of all tokens."""
        return self.store.findall('tokens')

    def update_token(self, tokid, update):
        """Update a token."""
        token = self.store.findone('tokens', '$id = ?', (tokid,))
        if token is None:
            raise NotFound('no such token: {0!r}'.format(name))
        update_dict(token, update)
        vres = va_token.validate(token)
        if vres.error:
            raise ValidationError('invalid update: {0}'.format(vres.error))
        self.store.update('tokens', token, '$id = ?', (tokid,))
        return token

    def delete_token(self, tokid):
        """Delete the authentication token *tokid*."""
        token = self.store.findone('tokens', '$id = ?', (tokid,))
        if token is None:
            raise NotFound('no such token {0!r}'.format(tokid))
        self.store.delete('tokens', '$id = ?', (tokid,))

    def validate_token(self, tokid, allow=None):
        """Validate a token."""
        token = self.store.findone('tokens', '$id = ?', (tokid,))
        if token is None:
            return False
        expires = token['expires']
        if expires and expires < time.time():
            return False
        if allow and not token['allow'].get(allow):
            return False
        return True

    # Vaults

    def _get_vault(self, uuid):
        """Filter unnecessary information from a vault object."""
        return copy_dict(self._vaults[uuid], exclude=('keys',))

    def create_vault(self, template):
        """Create a new vault.
        
        The newly created vault is created based on *template*. The vault will
        start unlocked, and no fields will be cached.
        """
        vres = va_vault_tmpl.validate(template)
        if vres.error:
            raise ValidationError('illegal vault template: {0!r}'.format(vres.error))
        uuid = template.get('id')
        if uuid is not None and uuid in self._vaults:
            raise Exists('vault already exists: {0!r}'.format(uuid))
        vault = copy_dict(template, exclude=('password',))
        if uuid is None:
            uuid = vault['id'] = crypto.random_uuid()
        vault['node'] = crypto.random_uuid()
        self._log.debug('creating new vault {!r}', abbr(uuid))
        self._log.debug('vault node is {!r}', abbr(vault['node']))
        keys = self._create_vault_keys()
        self._decrypted_keys[uuid] = keys
        # Encrypt the "sign" and "encrypt" keys but not the "auth" key. This
        # allows synchronization while a vault is locked. An auth key only
        # allows access to encrypted data, which you already have if you
        # managed to read it from the store in the first place.
        vault['keys'] = {}
        password = template['password']
        vault['keys']['sign'] = self._encrypt_vault_key(keys['sign'], password)
        vault['keys']['encrypt'] = self._encrypt_vault_key(keys['encrypt'], password)
        vault['keys']['auth'] = self._encrypt_vault_key(keys['auth'], '')
        self._log.debug('encrypted vault keys')
        self.store.insert('vaults', vault)
        self._log.debug('added new vault to store')
        self._vaults[uuid] = vault
        self._next_seqnr[uuid] = 0
        self._secret_index[uuid] = {}
        self._secret_cache[uuid] = SkipList()
        self._cached_fields[uuid] = set()
        self._linear_history[uuid] = {}
        self._full_history[uuid] = {}
        self._trusted_certs[uuid] = {}
        # Add a self-signed certificate. This makes _load_certificates()
        # trust our own keys without need for special casing.
        cert = {'node': vault['node'], 'name': util.gethostname(), 'keys': {}}
        for keyname in vault['keys']:
            key = copy_dict(vault['keys'][keyname], include=('public', 'keytype'))
            cert['keys'][keyname] = key
        item = self._new_certificate(uuid, cert)
        self._add_origin(uuid, item)
        self._sign_item(uuid, item)
        count = self.import_items(uuid, [item])
        self._log.debug('added self-signed certificate to store')
        assert count == 1
        vault = self._get_vault(uuid)
        self.raise_event('VaultCreated', vault)
        return vault

    def get_vault(self, uuid):
        """Return the vault with *uuid*.

        If the vault does not exist, None is returned.
        """
        if uuid not in self._vaults:
            return
        return self._get_vault(uuid)

    def get_vaults(self):
        """Return a list of all vaults."""
        return [self._get_vault(uuid) for uuid in self._vaults]

    def get_vault_status(self, uuid):
        """Return the vault status, either 'LOCKED' or 'UNLOCKED'."""
        if uuid not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(uuid))
        return 'UNLOCKED' if 'sign' in self._decrypted_keys[uuid] else 'LOCKED'

    def get_vault_statistics(self, uuid):
        """Return some statistics for a vault."""
        assert uuid in self._vaults
        stats = {}
        stats['current_secrets'] = len(self._secret_cache[uuid])
        stats['total_secrets'] = len(self._linear_history[uuid])
        linsize = sum((len(h) for h in self._linear_history[uuid].items()))
        stats['linear_history_size'] = linsize
        fullsize = sum((len(h) for h in self._full_history[uuid].items()))
        stats['full_history_size'] = fullsize
        result = self.store.execute("""
                    SELECT COUNT(*) FROM items WHERE $vault = ?
                    """, (uuid,))
        stats['total_items'] = result[0][0]
        result = self.store.execute("""
                    SELECT COUNT(*) FROM items WHERE $vault = ?
                    AND $payload$type = 'Certificate'
                    """, (uuid,))
        stats['total_certificates'] = result[0][0]
        result = self.store.execute("""
                    SELECT COUNT(*) FROM
                    (SELECT DISTINCT $payload$node FROM items
                     WHERE $vault = ? AND $payload$type = 'Certificate')
                    """, (uuid,))
        stats['total_nodes'] = result[0][0]
        stats['trusted_nodes'] = len(self._trusted_certs[uuid])
        return stats

    def update_vault(self, uuid, update):
        """Update a vault.

        The updated vault is returned.
        """
        if uuid not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(uuid))
        vres = va_vault_upd.validate(update)
        if not vres.match:
            raise ValidationError('illegal update: {0}'.format(vres.error))
        vault = self._vaults[uuid]
        password = update.get('password')
        if password is not None:
            if 'sign' not in self._decrypted_keys[uuid]:
                raise VaultLocked('cannot update password when locked')
            for keyname in 'sign', 'encrypt':
                key = self._decrypted_keys[uuid][keyname]
                vault['keys'][keyname] = self._encrypt_vault_key(key, password)
            self._log.debug('updated vault password')
        update = copy_dict(update, exclude=('password',))
        if update:
            update_dict(vault, update)
            self._log.debug('updated {} vault attributes', len(update))
        self.store.update('vaults', vault, '$id = ?', (uuid,))
        self._log.debug('saved back vault to store')
        vault = self._get_vault(uuid)
        self.raise_event('VaultUpdated', vault)
        return vault

    def delete_vault(self, uuid):
        """Delete a vault and all its secrets.

        This is an irreversible operation. The vault and its secrets are
        removed from the store.
        """
        if uuid not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(uuid))
        self.store.delete('vaults', '$id = ?', (uuid,))
        self.store.delete('items', '$vault = ?', (uuid,))
        self._log.debug('deleted vault entities from store')
        # The vacuum() here ensures that the data we just deleted is removed
        # from the sqlite database file. However, quite likely the data is
        # still on the disk, at least for some time. So this is definitely not
        # a secure delete.
        self.store.execute('VACUUM')
        self._log.debug('compacted the store')
        del self._vaults[uuid]
        del self._next_seqnr[uuid]
        del self._decrypted_keys[uuid]
        del self._trusted_certs[uuid]
        del self._secret_index[uuid]
        del self._secret_cache[uuid]
        del self._cached_fields[uuid]
        del self._linear_history[uuid]
        del self._full_history[uuid]
        self._log.debug('cleaned up all caches')
        self.raise_event('VaultDeleted', uuid)

    def unlock_vault(self, uuid, password, cache_fields=()):
        """Unlock a vault.
        
        Unlocking a vault decrypts the private keys that are stored in the
        store and stores them in memory. It will also decrypt all secrets in
        the vault and make an in-memory index for them. Additionally, all
        fields in *cache_fields* will be cached in memory as well.

        It is not an error to unlock a vault that is already unlocked. This
        can be used to add to the set of fields that are cached for a vault.
        """
        if uuid not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(uuid))
        assert uuid in self._decrypted_keys
        # Need to unlock? The vault may already be unlocked and user may just
        # want to update the cached fields.
        if 'sign' in self._decrypted_keys[uuid]:
            unlocked = False
        else:
            vault = self._vaults[uuid]
            for keyname in ('sign', 'encrypt'):
                key = self._decrypt_vault_key(vault['keys'][keyname], password)
                self._decrypted_keys[uuid][keyname] = key
            self._log.debug('unlocked vault {!r} ({!r})', abbr(uuid), vault['name'])
            unlocked = True
        # Need to (re)create the secret cache?
        fields = set(cache_fields)
        if not self._cached_fields[uuid].issuperset(fields):
            self._cached_fields[uuid].update(fields)
            self._secret_cache[uuid].clear()
            self._secret_index[uuid].clear()
            self._linear_history[uuid].clear()
            self._full_history[uuid].clear()
            self._load_secrets(uuid)
            self._log.debug('re-initialized secret cache')
        if unlocked:
            self.raise_event('VaultUnlocked', uuid)

    def lock_vault(self, uuid):
        """Lock a vault.
        
        This destroys the decrypted private keys and any secrets that are
        cached.
        """
        if uuid not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(uuid))
        assert uuid in self._decrypted_keys
        if 'sign' not in self._decrypted_keys[uuid]:
            return  # already locked
        del self._decrypted_keys[uuid]['sign']
        del self._decrypted_keys[uuid]['encrypt']
        self._secret_index[uuid].clear()
        self._secret_cache[uuid].clear()
        self._cached_fields[uuid].clear()
        self._linear_history[uuid].clear()
        self._full_history[uuid].clear()
        vault = self._vaults[uuid]
        self._log.debug('locked vault {!r} ({!r})', abbr(uuid), vault['name'])
        self.raise_event('VaultLocked', uuid)

    # Secrets

    def create_secret(self, vault, template):
        """Create a new secret and add it to a vault."""
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        assert vault in self._decrypted_keys
        if 'sign' not in self._decrypted_keys[vault]:
            raise VaultLocked('vault {0!r} is locked'.format(vault))
        assert vault in self._secret_cache
        vres = va_secret_tmpl.validate(template)
        if vres.error:
            raise ValidationError('illegal template: {0!r}'.format(vres.error))
        item = self._new_secret(vault, template)
        self._encrypt_item(vault, item)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        count = self.import_items(vault, [item])
        assert count == 1
        return copy_dict(item['payload'])

    def get_secret(self, vault, uuid):
        """Get a single current secret.

        The secret is a full secret containing all of its fields.
        """
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        assert vault in self._decrypted_keys
        if 'sign' not in self._decrypted_keys[vault]:
            raise VaultLocked('vault {0!r} is locked'.format(vault))
        assert vault in self._secret_cache
        secret = self._secret_cache[vault].search(uuid)
        if secret is None:
            return
        verid = secret['version']
        assert verid in self._secret_index[vault]
        itmid = self._secret_index[vault][verid]
        # Read the full item from disk, as the _secret_cache only contains
        # fields marked explicitly as cached. This is done to allow for bigger
        # items, and also not to have the full set of sensitive data in memory
        # all the time.
        item = self.store.findone('items', '$id = ?', (itmid,))
        if not va_item.match(item) or \
                not va_enc.match(item) or \
                not self._verify_item(vault, item) or \
                not self._decrypt_item(vault, item) or \
                not va_secret.match(item):
            self._log.error('item {!r} is corrupt in store', abbr(itmid))
            return
        self._log.debug('item {!r} was loaded from store', abbr(itmid))
        return copy_dict(item['payload'])

    def get_secrets(self, vault, after=None, maxitems=1000):
        """Return a all current secrets in a vault.

        This returns a list of partial secrets. A partial secret contains the
        envelope, and the fields that are cached. The fields to cache for a
        vault is specified using the *cache_fields* argument to
        :meth:`unlock_vault`. To get a full secret, use :meth:`get_secret`.
        """
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        assert vault in self._decrypted_keys
        if 'sign' not in self._decrypted_keys[vault]:
            raise VaultLocked('vault {0!r} is locked'.format(vault))
        assert vault in self._secret_cache
        # This returns the partial secrets only containing cached fields.
        secrets = []
        for (uuid, secret) in self._secret_cache[vault].items(start=after):
            if after is None or uuid > after:
                secrets.append(copy_dict(secret))
            if len(secrets) == maxitems:
                break
        return secrets

    def update_secret(self, vault, uuid, update):
        """Update an existing secret.

        The *update* argument must be a dictionary with the updates to perform.
        It has the same format as the *template* argument to
        :meth:`create_secret`. The update is relative: only fields that are
        specified are updated. To remove a field, set its value to ``None``.

        The updated secret is returned.
        """
        parent = self.get_secret(vault, uuid)
        if parent is None:
            raise NotFound('no such secret: {0!r}'.format(uuid))
        vres = va_secret_tmpl.validate(update)
        if vres.error:
            raise ModelError('illegal update: {!r}'.format(vres.error))
        template = copy_dict(parent, include=('fields',))
        update_dict(template, update)
        item = self._new_secret(vault, template, parent)
        self._encrypt_item(vault, item)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        count = self.import_items(vault, [item])
        assert count == 1
        return copy_dict(item['payload'])
 
    def delete_secret(self, vault, uuid):
        """Delete an existing secret.

        Deleting a secrets adds a new version for the secret without and fields
        and with the "deleted" attribute in the envelope set to ``True``.

        A deleted secret may be undeleted at any time by adding a new version
        for it, using :meth:`update_secret`.

        The new version is returned.
        """
        parent = self.get_secret(vault, uuid)
        if parent is None:
            raise NotFound('no such secret: {0!r}'.format(uuid))
        item = self._new_secret(vault, {'deleted': True, 'fields': {}}, parent)
        self._encrypt_item(vault, item)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        count = self.import_items(vault, [item])
        assert count == 1
        return copy_dict(item['payload'])
 
    def get_secret_history(self, vault, uuid, full=False):
        """Return the history for a secret.

        If *full* is False, the linear history is returned. This is a sequence
        of the current version (as returned by :meth:`get_secret`), followed by
        its ancestors, in-order.

        If *full* is True, then the full history is returned. This is an
        unordered sequence of all versions of the secret. It includes abandoned
        branches in the history.

        In both cases, there may be deleted versions in the result. These have
        the "deleted" attribute in the envelope set to ``True``.
        """
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        assert vault in self._decrypted_keys
        if 'sign' not in self._decrypted_keys[vault]:
            raise VaultLocked('vault {0!r} is locked'.format(vault))
        assert vault in self._linear_history
        if uuid not in self._linear_history[vault]:
            raise NotFound('no such secret: {0!r}'.format(uuid))
        hist = self._full_history if full else self._linear_history
        return copy_dict(hist[vault][uuid])

    # Synchronization

    def get_auth_key(self, vault):
        """Return the private authentication key for *vault*.

        The authentication key is always available, even if the vault is
        locked. This is unlike the sign and encryption keys, that are only
        available when a vault is unlocked.
        """
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        return self._decrypted_keys[vault]['auth']['private']

    def get_public_keys(self, vault):
        """Return a dictionary with all public keys."""
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        keys = {}
        for keyname,key in self._vaults[vault]['keys'].items():
            keys[keyname] = copy_dict(key, include=('public', 'keytype'))
        return keys

    def get_vector(self, vault):
        """Return a vector containing the latest items for each node that
        we know of."""
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        vector = self.store.execute("""
                    SELECT $origin$node,MAX($origin$seqnr)
                    FROM items
                    WHERE $vault = ?
                    GROUP BY $origin$node""", (vault,))
        return vector

    def get_certificate(self, vault, node):
        """Return a certificate for `node` in `vault`, if there is one."""
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        if node not in self._trusted_certs[vault]:
            return
        return copy_dict(self._trusted_certs[vault][node])

    def create_certificate(self, vault, template):
        """Create a new certificate and import it into the vault.

        This establishes a trust relationship with the certificate's node. If
        the certificate has the "decrypt_secret" access right then new versions
        for all secrets are added with a decryption key for the new node.
        """
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        assert vault in self._decrypted_keys
        if 'sign' not in self._decrypted_keys[vault]:
            raise VaultLocked('vault {0!r} is locked'.format(vault))
        vres = va_cert_tmpl.validate(template)
        if vres.error:
            raise ValidationError('invalid cert: {0}'.format(vres.error))
        # Before adding the new cert, find the nodes able to decrypt now.
        old_decrypt = set()
        for node,cert in self._trusted_certs[vault].items():
            if cert['keys'].get('encrypt'):
                old_decrypt.add(node)
        # Add the new cert
        item = self._new_certificate(vault, template)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        self._log.info('created cert {!r} for node {!r}',
                       abbr(item['payload']['id']), abbr(item['payload']['node']))
        count = self.import_items(vault, [item])
        assert count == 1
        # Determine the set of nodes able to decrypt after the cert has been
        # added. The cert may be for a new node with a "sign" key, but it could
        # also have made existing certs valid.
        new_decrypt = set()
        for node,cert in self._trusted_certs[vault].items():
            if cert['keys'].get('encrypt'):
                new_decrypt.add(node)
        assert new_decrypt.issuperset(old_decrypt)
        new_nodes = new_decrypt - old_decrypt
        if new_nodes:
            self._log.info('{} new nodes got the ability to decrypt', len(new_nodes))
            self._readdress_secrets(vault)
        else:
            self._log.info('no changes in set of nodes that can decrypt')
        return copy_dict(item['payload'])

    def get_items(self, vault, vector=None):
        """Return the items in `vault` that are newer than `vector`."""
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        if vector is not None:
            if not isinstance(vector, (tuple, list)):
                raise ModelError('illegal vector')
            for elem in vector:
                if not isinstance(elem, (tuple, list)) or len(elem) != 2 or \
                        not isinstance(elem[0], six.string_types) or \
                        not isinstance(elem[1], six.integer_types):
                    raise ModelError('illegal vector')
        query = '$vault = ?'
        args = [vault]
        if vector is not None:
            nodes = self.store.execute('SELECT DISTINCT $origin$node FROM items')
            terms = []
            vector = dict(vector)
            for node, in nodes:
                if node in vector:
                    terms.append('($origin$node = ? AND $origin$seqnr > ?)')
                    args += [node, vector[node]]
                else:
                    terms.append('$origin$node = ?')
                    args.append(node)
            query += ' AND (%s)' % ' OR '.join(terms)
        return self.store.findall('items', query, args)

    def import_items(self, vault, items):
        """Import multiple items.
        
        The items are validated and stored. If required, the certificate and
        secret caches are updated.

        The return value is the number of items imported.
        """
        if vault not in self._vaults:
            raise NotFound('no such vault: {0!r}'.format(vault))
        self._log.debug('importing {} items', len(items))
        # Check all items are for the indicated vault and well formed
        items = [item for item in items if item['vault'] == vault]
        self._log.debug('{} items are for the correct vault', len(items))
        items = [item for item in items if va_item.match(item)]
        self._log.debug('{} items are well formed', len(items))
        # Weed out items we already have.
        oldvec = self.get_vector(vault)
        vec = dict(oldvec)
        isnew = lambda it: it['origin']['seqnr'] > vec.get(it['origin']['node'], -1)
        items = [item for item in items if isnew(item)]
        self._log.debug('{} items are new', len(items))
        # Import any cert or secret that is well formed and new. It is safe to
        # do so, because merely being in the database doesn't convey any trust.
        # All items need to be signed by a node with a certificate that has valid
        # trust chain back to ourselves.
        iscert = lambda it: it['payload']['type'] == 'Certificate' and va_cert.match(it)
        certs = [item for item in items if iscert(item)]
        self._log.debug('{} new items are well formed certificates', len(certs))
        isenc = lambda it: it['payload']['type'] == 'Encrypted' and va_enc.match(it)
        encitems = [item for item in items if isenc(item)]
        self._log.debug('{} new items are well formed encrypted items', len(encitems))
        with self.store.begin():
            for item in certs:
                self.store.insert('items', item)
            for item in encitems:
                self.store.insert('items', item)
        self._log.debug('{} items were added', len(certs) + len(encitems))
        # Now see what caches need to be updated. First figure out certs. If
        # any got added, we need to re-establish the set of valid signer certs. 
        if certs:
            old_signers = set()
            for node,cert in self._trusted_certs[vault].items():
                if cert['keys'].get('sign'):
                    old_signers.add(node)
            self._load_certificates(vault)
            new_signers = set()
            for node,cert in self._trusted_certs[vault].items():
                if cert['keys'].get('sign'):
                    new_signers.add(node)
            assert new_signers.issuperset(old_signers)
            new_signers -= old_signers
            self._log.debug('{} new nodes got the ability to sign', len(new_signers))
        else:
            new_signers = set()
        # If the vault is unlocked, verify and decrypt the items, and update
        # the secrets cache. If the vault is locked, we are done. The
        # verification will be done by _load_secrets() when the vault is unlocked.
        if 'sign' in self._decrypted_keys[vault]:
            self._log.debug('vault is unlocked, updating secret cache')
            # Now update the secret cache for 1. any secret that got added, and
            # 2. any secret that is signed by a new signer node.
            if new_signers:
                query = "$vault = ? AND $payload$type = 'Encrypted'"
                query += " AND ({0})".format(" OR ".join(["$origin$node = ?"] * len(new_signers)))
                args = [vault] + list(new_signers)
                certitems = self.store.findall('items', query, args)
                self._log.debug('{} items are possibly touched by the new certs', len(certitems))
            else:
                certitems = []
            secrets = []
            for item in itertools.chain(encitems, certitems):
                if not self._verify_item(vault, item) or \
                        not self._decrypt_item(vault, item) or \
                        not va_secret.match(item):
                    continue
                secrets.append(item)
            updated = self._update_secret_cache(vault, secrets)
            self._log.debug('updated secret cache with {} secrets', len(secrets))
            self._log.debug('these results in {} new active secrets', len(updated))
            for i in range(0, len(updated), 100):
                batch = [copy_dict(s) for s in updated[i:i+100]]
                self.raise_event('SecretsAdded', vault, batch)
        else:
            self._log.debug('vault is locked, not updating secret cache')
        self.raise_event('ItemsAdded', vault, oldvec)
        return len(certs) + len(encitems)
