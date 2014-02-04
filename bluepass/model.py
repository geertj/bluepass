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

import gruvi
from gruvi import compat

from . import base64, json, logging, validate, crypto, util
from .errors import *

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
        { id: str@>=20, expires: int>=0, rights:
            { control_api: *bool, client_api: *bool } }
        """)

va_vault = validate.compile("""
        { id: uuid, name: str@>0@<=100, node: uuid, keys:
            { sign:
                { keytype: str="rsa", private: b64@>=16, public: b64@>=16, encinfo:
                    { algo: str="aes-cbc-pkcs7", iv: b64@>=16, kdf:str="pbkdf2-hmac-sha1",
                      salt: b64@>=16, count: int>0, length: int>0 },
                  pwcheck:
                    { algo: str="hmac-random-sha256", random: b64@>=16, verifier: b64@>=16 } }
              encrypt:
                { keytype: str="rsa", private: b64@>=16, public: b64@>=16, encinfo:
                    { algo: str="aes-cbc-pkcs7", iv: b64@>=16, kdf:str="pbkdf2-hmac-sha1",
                      salt: b64@>=16, count: int>0, length: int>0 },
                  pwcheck:
                    { algo: str="hmac-random-sha256", random: b64@>=16, verifier: b64@>=16 } }
              auth:
                { keytype: str="rsa", private: b64@>=16, public: b64@>=16, encinfo:
                    { algo: str="plain" } } } }
        """)

va_vault_update = validate.compile('{name: str@>0@<=100}')

va_item = validate.compile("""
        { id: uuid, type: str="Item", vault: uuid,
          origin: { node: uuid, seqnr: int>=0 },
          payload: { type: str="Certificate"|="EncryptedItem", ... }
          signature: { algo: str="rsa-pss-sha256", blob: b64@>=16 } }
        """)

va_cert = validate.compile("""
        { id: uuid, payload:
            {  id: uuid, type:str="Certificate", node: uuid, name: str@>0@<=100, keys:
                { sign: { key: b64, keytype: str="rsa" },
                  encrypt: { key: b64, keytype: str="rsa" },
                  auth: { key: b64, keytype: str="rsa" } }
               restrictions: { synconly: *bool } }, ... }
        """)

va_encitem = validate.compile("""
        { id: uuid, payload:
            { type: str="EncryptedItem", algo: str="aes-cbc-pkcs7",
              iv: b64@>=16 blob: b64@>=2, keyalgo: str="rsa-oaep", keys: {...} }, ... }
        """)

# XXX: Check encitems/payload/keys: uuid -> b64

va_decitem = validate.compile("""
        { id: uuid, payload: { id: uuid, type: str="Version", ... }, ... }
        """)

va_version = validate.compile("""
        { id: uuid, payload:
            { id: uuid, type: str="Version", parent: *uuid, deleted: *bool,
              created_at: int>=0, version: { id: uuid, ... } }, ... }
        """)

va_certinfo = validate.compile("""
        { node: uuid, name: str@>0@<=100, keys:
            { sign: { key: b64@>=16, keytype: str="rsa" },
              encrypt: { key: b64@>=16, keytype: str="rsa" },
              auth: { key: b64@>=16, keytype: str="rsa" } }
          restrictions: { synconly: *bool } }
        """)


def filter_dict(d, include=None, exclude=None):
    """Filter keys from a dict (or list of dicts)."""
    if d is None:
        return
    elif isinstance(d, list):
        return [filter_dict(elem, include, exclude) for elem in d]
    res = {}
    for key in d:
        if include is not None:
            if key in include:
                res[key] = d[key]
        elif exclude is not None:
            if key not in exclude:
                res[key] = d[key]
    return res

def filter_vault(vault):
    """Filter unnecessary information from a vault object."""
    return filter_dict(vault, exclude=('keys',))


class Model(object):
    """This class implements our vault/item model on top of a document
    store."""

    def __init__(self, store):
        """Create a new model on top of *store*."""
        self.store = store
        self._tokens = {}
        self.vaults = {}
        self._log = logging.get_logger(self)
        self._next_seqnr = {}
        self._private_keys = {}
        self._trusted_certs = {}
        self._version_cache = {}
        self._linear_history = {}
        self._full_history = {}
        self.callbacks = []
        self._update_schema()
        self._load_tokens()
        self._load_vaults()

    def _update_schema(self):
        """Create or update the document store."""
        store = self.store
        if 'configs' not in store.collections:
            store.create_collection('configs')
        if 'tokens' not in store.collections:
            store.create_collection('tokens')
        if 'vaults' not in store.collections:
            store.create_collection('vaults')
        if 'items' not in store.collections:
            store.create_collection('items')
            store.create_index('items', '$vault', 'TEXT')
            store.create_index('items', '$origin$node', 'TEXT')
            store.create_index('items', '$origin$seqnr', 'INT')
            store.create_index('items', '$payload$type', 'TEXT')

    def _load_tokens(self):
        """Load all tokens."""
        total = invalid = 0
        tokens = self.store.findall('tokens')
        for token in tokens:
            total += 1
            vres = va_token.validate(token)
            if not vres.match:
                self._log.error('Invalid token "{}": {}', token, vres.error)
                invalid += 1
                continue
            self._tokens[token['id']] = token
        self._log.info('Database contains {} tokens ({} invalid)', total, invalid)

    def _check_items(self, vault):
        """Check all items in a vault."""
        total = errors = 0
        items = self.store.findall('items', '$vault = ?', (vault,))
        self._log.debug('Checking all items in vault "{}"', vault)
        for item in items:
            uuid = item.get('id', '<no id>')
            vres = va_item.validate(item)
            if not vres:
                self._log.error('Invalid item "{}": {}', uuid, vres.errors[0])
                errors += 1
                continue
            typ = item['payload']['type']
            if typ == 'Certificate':
                vres = va_cert.validate(item)
                if not vres:
                    self._log.error('Invalid certificate "{}": {}', uuid, vres.errors[0])
                    errors += 1
                    continue
            elif typ == 'EncryptedItem':
                vres = va_encitem.validate(item)
                if not vres:
                    self._log.error('Invalid encrypted item "{}": {}', uuid, vres.errors[0])
                    errors += 1
                    continue
            else:
                self_log.error('Unknown payload type "{}" in item "{}"', typ, item['id'])
                continue
            total += 1
        self._log.debug('Vault "{}" contains {} items and {} errors', vault, total, errors)
        return errors == 0

    def _load_vault(self, vault):
        """Check and load a single vault."""
        uuid = vault.get('id', '<no id>')
        vres = va_vault.validate(vault)
        if not vres:
            self._log.error('Vault "{}" has errors (skipping): {}', uuid, vres.errors[0])
            return False
        uuid = vault['id']
        if not self._check_items(vault['id']):
            self._log.error('Vault {} has items with errors, skipping', uuid)
            return False
        self.vaults[uuid] = vault
        self._private_keys[uuid] = []
        self._version_cache[uuid] = {}
        self._linear_history[uuid] = {}
        self._full_history[uuid] = {}
        seqnr = self.store.execute('items', """
                SELECT MAX($origin$seqnr)
                FROM items
                WHERE $origin$node = ? AND $vault = ?
                """, (vault['node'], vault['id']))
        if seqnr:
            self._next_seqnr[uuid] = seqnr[0][0] + 1
        else:
            self._next_seqnr[uuid] = 0
        self._log.debug('Succesfully loaded vault "{}" ({})', uuid, vault['name'])
        return True

    def _load_vaults(self):
        """Check and load all vaults."""
        total = errors = 0
        filename = self.store.filename
        self._log.debug('loading all vaults from store {}', filename)
        vaults = self.store.findall('vaults')
        for vault in vaults:
            total += 1
            if not self._load_vault(vault):
                errors += 1
                continue
            self._calculate_trust(vault['id'])
        self._log.debug('successfully loaded {} vaults, {} vaults had errors',
                        total-errors, errors)

    def _verify_signature(self, item, pubkey):
        """Verify the signature on an item."""
        assert va_item.match(item)
        signature = item.pop('signature')
        if signature['algo'] != 'rsa-pss-sha256':
            self._log.error('unknown signature algo "{}" for item "{}"', algo, item['id'])
            return False
        message = json.dumps_c14n(item).encode('utf8')
        blob = base64.decode(signature['blob'])
        try:
            status = crypto.rsa_verify(message, blob, pubkey, 'pss-sha256')
        except crypto.Error:
            log.error('garbage in signature for item "%s"', item['id'])
            return False
        if not status:
            log.error('invalid signature for item "%s"', item['id'])
            return False
        item['signature'] = signature
        return True

    def __collect_certs(self, node, nodekey, certs, result, depth):
        """Collect valid certificates."""
        if node not in certs:
            return
        result[node] = []
        for cert in certs[node]:
            if not self._verify_signature(cert, nodekey):
                continue
            synconly = cert['payload'].get('restrictions', {}).get('synconly', False)
            subject = cert['payload']['node']
            subjkey = base64.decode(cert['payload']['keys']['sign']['key'])
            if node == subject:
                # self-signed certificate
                result[node].append((depth+1+synconly*100, cert))
            else:
                result[node].append((depth+2+synconly*100, cert))
            if subject in result:
                # There are loops in the "signed by" graph because during
                # pairing nodes sign each other's key.
                continue
            if synconly:
                # Synconly certs are not allowed to sign items
                continue
            self.__collect_certs(subject, subjkey, certs, result, depth+2)

    def _calculate_trust(self, vault):
        """Calculate a list of trusted certificates."""
        assert vault in self.vaults
        # Create mapping of certificates by their signer
        certs = {}
        query = "$vault = ? AND $payload$type = 'Certificate'"
        result = self.store.findall('items', query, (vault,))
        for cert in result:
            assert va_item.match(cert)
            signer = cert['origin']['node']
            try:
                certs[signer].append(cert)
            except KeyError:
                certs[signer] = [cert]
        # Collect valid certs: a valid cert is one that is signed by a trusted
        # signing key. A trusted signing key is our own key, or a key that has
        # a valid certificate that does not have the "synconly" option.
        node = self.vaults[vault]['node']
        nodekey = base64.decode(self.vaults[vault]['keys']['sign']['public'])
        result = {}
        self.__collect_certs(node, nodekey, certs, result, 0)
        trusted_certs = {}
        for signer in result:
            for cert in result[signer]:
                subject = cert[1]['payload']['node']
                try:
                    trusted_certs[subject].append(cert)
                except KeyError:
                    trusted_certs[subject] = [cert]
        for subject in trusted_certs:
            certs = trusted_certs[subject]
            certs.sort()
            trusted_certs[subject] = [ cert[1] for cert in certs ]
        ncerts = sum([len(certs) for certs in trusted_certs.items()])
        self._log.debug('there are {} trusted certs for vault "{}"', ncerts, vault)
        self._trusted_certs[vault] = trusted_certs

    def _update_version_cache(self, items, notify=True, local=True):
        """Update the version cache for `items'. If `notify` is True,
        callbacks will be run."""
        grouped = {}
        for item in items:
            uuid = item['payload']['version']['id']
            try:
                grouped[uuid].append(item)
            except KeyError:
                grouped[uuid] = [item]
        changes = {}
        for uuid,versions in grouped.items():
            vault = versions[0]['vault']
            try:
                self._full_history[vault][uuid] += versions
            except KeyError:
                self._full_history[vault][uuid] = versions
            linear = self._sort_history(uuid, self._full_history[vault][uuid])
            self._linear_history[vault][uuid] = linear
            current = self._version_cache[vault].get(uuid)
            if not current and not linear[0]['payload'].get('deleted'):
                self._version_cache[vault][uuid] = linear[0]
            elif current and linear[0]['payload'].get('deleted'):
                del self._version_cache[vault][uuid]
            elif current and linear[0]['payload']['id'] != current['payload']['id']:
                self._version_cache[vault][uuid] = linear[0]
            else:
                continue
            if not notify:
                continue
            if vault not in changes:
                changes[vault] = []
            changes[vault].append(self._get_version(linear[0]))
        for vault in changes:
            self.raise_event('VersionsAdded', vault, changes[vault])

    def _clear_version_cache(self, vault):
        """Wipe and reset the version cache. Used when locking a vault."""
        if vault not in self._version_cache:
            return
        assert vault in self._linear_history
        assert vault in self._full_history
        self._version_cache[vault].clear()
        self._linear_history[vault].clear()
        self._full_history[vault].clear()

    def _sort_history(self, uuid, items):
        """Create a linear history for a set of versions. This is
        where our conflict resolution algorithm is implemented."""
        # Create a tree mapping parents to their children
        if not items:
            return []
        tree = {}
        parents = {}
        for item in items:
            parent = item['payload'].get('parent')
            try:
                tree[parent].append(item)
            except KeyError:
                tree[parent] = [item]
            parents[item['payload']['id']] = item
        # Our conflict resulution works like this: we find the leaf in the
        # tree with the highest created_at time. That is the current version.
        # The linear history of the current version are its ancestors.
        #
        # This algorithm protects us from nodes in the vault that have a wrong
        # clock. However, if two updates happen close enough that the entire
        # tree has not yet replicated, then the item with the highest created_at
        # will win, whether or not that is the version that was created last
        # according to a universal clock.
        leaves = []
        for item in items:
            if item['payload']['id'] in tree:
                continue  # not leaf
            leaves.append(item)
        assert len(leaves) > 0
        leaves.sort(key=lambda x: x['payload']['created_at'], reverse=True)
        history = [leaves[0]]
        parent = item['payload'].get('parent')
        while parent is not None and parent in parents:
            item = parents[parent]
            history.append(item)
            parent = item['payload'].get('parent')
        return history
 
    def _load_versions(self, vault):
        """Load all current versions and their history."""
        versions = []
        query = "$vault = ? AND $payload$type = 'EncryptedItem'"
        items = self.store.findall('items', query, (vault,))
        for item in items:
            if not self._verify_item(vault, item) or \
                    not self._decrypt_item(vault, item) or \
                    not va_decitem.match(item) or \
                    not va_version.match(item):
                continue
            versions.append(item)
        self._update_version_cache(versions, notify=False)
        cursize = len(self._version_cache[vault])
        linsize = sum((len(h) for h in self._linear_history[vault].items()))
        fullsize = sum((len(h) for h in self._full_history[vault].items()))
        self._log.debug('loaded {} versions from vault {}', cursize, vault)
        self._log.debug('linear history contains {} versions', linsize)
        self._log.debug('full history contains {} versions', fullsize)

    def _sign_item(self, vault, item):
        """Add a signature to an item."""
        assert vault in self.vaults
        assert vault in self._private_keys
        signature = {}
        signature['algo'] = 'rsa-pss-sha256'
        message = json.dumps_c14n(item).encode('utf8')
        signkey = self._private_keys[vault][0]
        blob = crypto.rsa_sign(message, signkey, 'pss-sha256')
        signature['blob'] = base64.encode(blob)
        item['signature'] = signature

    def _verify_item(self, vault, item):
        """Verify that an item has a correct signature and that it
        the signature was created by a trusted node."""
        signer = item['origin']['node']
        if signer not in self._trusted_certs[vault]:
            self._log.error('item {} was signed by unknown/untrusted node {}',
                            item['id'], signer)
            return False
        cert = self._trusted_certs[vault][signer][0]['payload']
        synconly = cert.get('restrictions', {}).get('synconly')
        if synconly:
            return False  # synconly certs may not sign items
        pubkey = base64.decode(cert['keys']['sign']['key'])
        return self._verify_signature(item, pubkey)

    def _encrypt_item(self, vault, item):
        """INTERNAL: Encrypt an item."""
        assert vault in self.vaults
        assert vault in self._private_keys
        clear = item.pop('payload')
        item['payload'] = payload = {}
        payload['type'] = 'EncryptedItem'
        payload['algo'] = 'aes-cbc-pkcs7'
        iv = crypto.random_bytes(16)
        payload['iv'] = base64.encode(iv)
        symkey = crypto.random_bytes(16)
        message = json.dumps(clear).encode('utf8')
        blob = crypto.aes_encrypt(message, symkey, iv, 'cbc-pkcs7')
        payload['blob'] = base64.encode(blob)
        payload['keyalgo'] = 'rsa-oaep'
        payload['keys'] = keys = {}
        # encrypt the symmetric key to all nodes in the vault including ourselves
        for node in self._trusted_certs[vault]:
            cert = self._trusted_certs[vault][node][0]['payload']
            synconly = cert.get('restrictions', {}).get('synconly')
            if synconly:
                # do not encrypt items to "synconly" nodes
                continue
            pubkey = base64.decode(cert['keys']['encrypt']['key'])
            enckey = crypto.rsa_encrypt(symkey, pubkey, 'oaep')
            keys[node] = base64.encode(enckey)

    def _decrypt_item(self, vault, item):
        """INTERNAL: decrypt an encrypted item."""
        assert vault in self.vaults
        assert vault in self._private_keys
        algo = item['payload']['algo']
        keyalgo = item['payload']['keyalgo']
        if algo != 'aes-cbc-pkcs7':
            self._log.error('unknow algo in encrypted payload in item {}: {}', item['id'], algo)
            return False
        if keyalgo != 'rsa-oaep':
            self._log.error('unknow keyalgo in encrypted payload in item {}: {}', item['id'], algo)
            return False
        node = self.vaults[vault]['node']
        keys = item['payload']['keys']
        if node not in keys:
            self._log.info('item {} was not encrypted to us, skipping', item['id'])
            return False
        try:
            enckey = base64.decode(keys[node])
            privkey = self._private_keys[vault][1]
            symkey = crypto.rsa_decrypt(enckey, privkey, 'oaep')
            blob = base64.decode(item['payload']['blob'])
            iv = base64.decode(item['payload']['iv'])
            clear = crypto.aes_decrypt(blob, symkey, iv, 'cbc-pkcs7')
        except crypto.Error as e:
            self._log.error('could not decrypt encrypted payload in item {}: {}' % (item['id'], str(e)))
            return False
        payload = json.try_loads(clear.decode('utf8'))
        if payload is None:
            self._log.error('illegal JSON in decrypted payload in item {}', item['id'])
            return False
        item['payload'] = payload
        return True

    def _add_origin(self, vault, item):
        """Add the origin section to an item."""
        item['origin'] = origin = {}
        origin['node'] = self.vaults[vault]['node']
        origin['seqnr'] = self._next_seqnr[vault]
        self._next_seqnr[vault] += 1
        
    def _new_item(self, vault, ptype, **kwargs):
        """Create a new empty item."""
        item = {}
        item['id'] = crypto.random_uuid()
        item['type'] = 'Item'
        item['vault'] = vault
        item['payload'] = payload = {}
        payload['type'] = ptype
        payload.update(kwargs)
        return item

    def _new_certificate(self, vault, **kwargs):
        """Create anew certificate."""
        item = self._new_item(vault, 'Certificate', **kwargs)
        item['payload']['id'] = crypto.random_uuid()
        return item

    def _new_version(self, vault, version, parent=None):
        """Create a new empty version."""
        item = self._new_item(vault, 'Version')
        payload = item['payload']
        payload['id'] = crypto.random_uuid()
        payload['created_at'] = int(time.time())
        if parent is not None:
            payload['parent'] = parent
        payload['version'] = filter_dict(version, exclude=('vault', 'deleted', 'created_at'))
        return item

    def _get_version(self, item):
        """Return the version inside an item, with envelope."""
        payload = item['payload']
        version = payload['version'].copy()
        version['vault'] = item['vault']
        version['deleted'] = payload.get('deleted', False)
        version['created_at'] = payload['created_at']
        return version

    def _create_vault_key(self, password):
        """Create a new vault key. Return a tuple (private, public,
        keyinfo). The keyinfo structure contains the encrypted keys."""
        keyinfo = {}
        private, public = crypto.rsa_genkey(3072)
        keyinfo['keytype'] = 'rsa'
        keyinfo['public'] = base64.encode(public)
        keyinfo['encinfo'] = encinfo = {}
        if not password:
            encinfo['algo'] = 'plain'
            keyinfo['private'] = base64.encode(private)
            return private, public, keyinfo
        encinfo['algo'] = 'aes-cbc-pkcs7'
        iv = crypto.random_bytes(16)
        encinfo['iv'] = base64.encode(iv)
        prf = 'hmac-sha1'
        encinfo['kdf'] = 'pbkdf2-%s' % prf
        # Tune pbkdf2 so that it takes about 0.2 seconds (but always at
        # least 4096 iterations).
        count = max(4096, int(0.2 * crypto.pbkdf2_speed(prf)))
        self._log.debug('using {} iterations for PBKDF2', count)
        encinfo['count'] = count
        encinfo['length'] = 16
        salt = crypto.random_bytes(16)
        encinfo['salt'] = base64.encode(salt)
        symkey = crypto.pbkdf2(password, salt, encinfo['count'], encinfo['length'], prf)
        enckey = crypto.aes_encrypt(private, symkey, iv, 'cbc-pkcs7')
        keyinfo['private'] = base64.encode(enckey)
        keyinfo['pwcheck'] = pwcheck = {}
        pwcheck['algo'] = 'hmac-random-sha256'
        random = crypto.random_bytes(16)
        pwcheck['random'] = base64.encode(random)
        verifier = crypto.hmac(symkey, random, 'sha256')
        pwcheck['verifier'] = base64.encode(verifier)
        return private, public, keyinfo

    def _create_vault_keys(self, password):
        """Create all 3 vault keys (sign, encrypt and auth)."""
        # Generate keys in the CPU thread pool.
        dummy = crypto.pbkdf2_speed('hmac-sha1')
        pool = gruvi.ThreadPool.get_cpu_pool()
        fsign = pool.submit(self._create_vault_key, password)
        fencrypt = pool.submit(self._create_vault_key, password)
        fauth = pool.submit(self._create_vault_key, '')
        keys = { 'sign': fsign.result(), 'encrypt': fencrypt.result(),
                 'auth': fauth.result() }
        return keys
  
    # Events / callbacks

    def add_callback(self, callback):
        """Register a callback that that gets notified when one or more
        versions have changed."""
        self.callbacks.append(callback)

    def raise_event(self, event, *args):
        """Raise an event o all callbacks."""
        for callback in self.callbacks:
            try:
                callback(event, *args)
            except Exception as e:
                self._log.error('callback raised exception: {}' % str(e))

    # API for a typical GUI consumer

    def create_config(self, config):
        """Create a new configuration."""
        vres = va_config.validate(config)
        if vres.error:
            raise ValidationError('Invalid config: {0}'.format(vres.error))
        self.store.insert('configs', config)
        return config

    def get_config(self, name):
        """Return the configuration document."""
        return self.store.findone('configs', '$name = ?', (name,))

    def get_configs(self):
        """Return all configurations."""
        return self.store.findall('configs')

    def update_config(self, update):
        """Update the configuration document."""
        name = update.get('name')
        config = self.store.findone('configs', '$name = ?', (name,))
        if config is None:
            raise NotFound('No such config: {0}'.format(name))
        for key,value in update.items():
            if value is not None:
                config[key] = value
            elif key in config:
                del config[key]
        self.store.update('configs', config, '$name = ?', (name,))
        return config

    def delete_config(self, name):
        """Delete a configuration document."""
        config = self.store.findone('configs', '$name = ?', (name,))
        if config is None:
            raise NotFound('No such config: {0}'.format(name))
        self.store.delete('configs', '$name = ?', (name,))

    # Tokens

    def get_token(self, tokid):
        """Return the authentication token identified by *tokid*."""
        return self._tokens.get(tokid)

    def add_token(self, token):
        """Create a new authentication token *token*."""
        if 'id' not in token:
            token['id'] = crypto.random_cookie()
        vres = va_token.validate(token)
        if not vres.match:
            raise ValidationError('Invalid token: {0}'.format(vres.error))
        tokid = token['id']
        if tokid in self._tokens:
            raise ValidationError('Token already exists: {0}'.format(tokid))
        self._tokens[tokid] = token
        if token.get('expires', '0') != '0':
            self.store.insert('tokens', token)
        return token

    def delete_token(self, tokid):
        """Delete the authentication token *tokid*."""
        if tokid not in self._tokens:
            raise NotFound('No such token: {0}'.format(tokid))
        del self._tokens[tokid]
        self.store.delete('tokens', '$id = ?', (tokid,))

    def validate_token(self, tokid, right=None):
        """Validate a token."""
        token = self._tokens.get(tokid)
        if token is None:
            return False
        expires = token['expires']
        if expires and expires < time.time():
            return False
        if right and not token['rights'].get(right):
            return False
        return True

    # Vaults

    def create_vault(self, name, password, uuid=None, notify=True):
        """Create a new vault.
        
        The `name` argument specifies the name of the vault to create. The
        private keys for this vault are encrypted with `password'. If the
        `uuid` argument is given, a vault with this UUID is created. The
        default is to generate an new UUID for this vault. The `notify`
        arguments determines wether or not callbacks must be called when this
        vault is created.
        """
        if uuid is not None and uuid in self.vaults:
            raise ModelError('A vault with UUID {0} already exists}'.format(uuid))
        if not 0 < len(name) <= 100:
            raise ValidationError('Name must be 0 < length <= 100 characters')
        if not 0 < len(password) <= 100:
            raise ValidationError('Password must be 0 < length <= 100 characters')
        if isinstance(password, compat.text_type):
            password = password.encode('utf8')
        vault = {}
        if uuid is None:
            uuid = crypto.random_uuid()
        vault['id'] = uuid
        vault['name'] = name
        vault['node'] = crypto.random_uuid()
        keys = self._create_vault_keys(password)
        vault['keys'] = dict(((key, keys[key][2]) for key in keys))
        self.store.insert('vaults', vault)
        self.vaults[uuid] = vault
        # Start unlocked by default
        self._private_keys[uuid] = (keys['sign'][0], keys['encrypt'][0])
        self._version_cache[uuid] = {}
        self._linear_history[uuid] = {}
        self._full_history[uuid] = {}
        self._next_seqnr[uuid] = 0
        # Add a self-signed certificate
        certinfo = { 'node': vault['node'], 'name': util.gethostname() }
        keys = certinfo['keys'] = {}
        for key in vault['keys']:
            keys[key] = { 'key': vault['keys'][key]['public'],
                          'keytype': vault['keys'][key]['keytype'] }
        certinfo['restrictions'] = {}
        item = self._new_certificate(uuid, **certinfo)
        self._add_origin(uuid, item)
        self._sign_item(uuid, item)
        self.import_item(uuid, item, notify=notify)
        if notify:
            self.raise_event('VaultAdded', vault)
        return filter_vault(vault)

    def get_vault(self, uuid):
        """Return the vault with `uuid` or None if there is no such vault."""
        if uuid not in self.vaults:
            return
        vault = self.store.findone('vaults', '$id = ?', (uuid,))
        return filter_vault(vault)

    def get_vaults(self):
        """Return a list of all vaults."""
        return filter_vault(self.store.findall('vaults'))

    def update_vault(self, update):
        """Update a vault."""
        uuid = update['id']
        if uuid not in self.vaults:
            raise NotFound('No such vault: {0}'.format(uuid))
        vres = va_vault_update.validate(update)
        if not vres.match:
            raise ValidationError('Illegal vault update: {0}'.format(vres.error))
        vault = self.vaults[uuid]
        for key in update:
            vault[key] = update
        self.store.update('vaults', vault, '$id = ?', (vault['id'],))
        self.raise_event('VaultUpdated', vault)
        return filter_vault(vault)

    def delete_vault(self, uuid):
        """Delete a vault and all its items."""
        if uuid not in self.vaults:
            raise NotFound('No such vault: {0}'.format(uuid))
        vault = self.vaults[uuid]
        self.store.delete('vaults', '$id = ?', (uuid,))
        self.store.delete('items', '$vault = ?', (uuid,))
        # The VACUUM command here ensures that the data we just deleted is
        # removed from the sqlite database file. However, quite likely the
        # data is still on the disk, at least for some time. So this is not
        # a secure delete.
        self.store.execute('vaults', 'VACUUM')
        del self.vaults[uuid]
        del self._private_keys[uuid]
        del self._version_cache[uuid]
        del self._linear_history[uuid]
        del self._full_history[uuid]
        del self._next_seqnr[uuid]
        vault['deleted'] = True
        self.raise_event('VaultRemoved', vault)

    def get_vault_statistics(self, uuid):
        """Return some statistics for a vault."""
        if uuid not in self.vaults:
            raise NotFound('No such vault: {0}'.format(uuid))
        stats = {}
        stats['current_versions'] = len(self._version_cache[uuid])
        stats['total_versions'] = len(self._linear_history[uuid])
        linsize = sum((len(h) for h in self._linear_history[uuid].items()))
        stats['linear_history_size'] = linsize
        fullsize = sum((len(h) for h in self._full_history[uuid].items()))
        stats['full_history_size'] = fullsize
        result = self.store.execute('items', """
                    SELECT COUNT(*) FROM items WHERE $vault = ?
                    """, (uuid,))
        stats['total_items'] = result[0]
        result = self.store.execute('items', """
                    SELECT COUNT(*) FROM items WHERE $vault = ?
                    AND $payload$type = 'Certificate'
                    """, (uuid,))
        stats['total_certificates'] = result[0]
        result = self.store.execute('items', """
                    SELECT COUNT(*) FROM
                    (SELECT DISTINCT $payload$node FROM items
                     WHERE $vault = ? AND $payload$type = 'Certificate')
                    """, (uuid,))
        stats['total_nodes'] = result[0]
        stats['trusted_nodes'] = len(self._trusted_certs[uuid])
        return stats

    def unlock_vault(self, uuid, password):
        """Unlock a vault.
        
        The vault `uuid` is unlocked using `password`. This decrypts the
        private keys that are stored in the database and stored them in
        memory. It is not an error to unlock a vault that is already unlocked.
        """
        if uuid not in self.vaults:
            raise NotFound('No such vault: {0}'.format(uuid))
        assert uuid in self._private_keys
        if len(self._private_keys[uuid]) > 0:
            return
        if isinstance(password, compat.text_type):
            password = password.encode('utf8')
        for key in ('sign', 'encrypt'):
            keyinfo = self.vaults[uuid]['keys'][key]
            pubkey = base64.decode(keyinfo['public'])
            privkey = base64.decode(keyinfo['private'])
            encinfo = keyinfo['encinfo']
            pwcheck = keyinfo['pwcheck']
            # These are enforced by va_vault.match()
            assert encinfo['algo'] == 'aes-cbc-pkcs7'
            assert encinfo['kdf'] == 'pbkdf2-hmac-sha1'
            assert pwcheck['algo'] == 'hmac-random-sha256'
            salt = base64.decode(encinfo['salt'])
            iv = base64.decode(encinfo['iv'])
            prf = encinfo['kdf'][7:]
            symkey = crypto.pbkdf2(password, salt, encinfo['count'], encinfo['length'], prf)
            random = base64.decode(pwcheck['random'])
            verifier = base64.decode(pwcheck['verifier'])
            check = crypto.hmac(symkey, random, 'sha256')
            if check != verifier:
                raise ModelError('WrongPassword')
            private = crypto.aes_decrypt(privkey, symkey, iv, 'cbc-pkcs7')
            self._private_keys[uuid].append(private)
        self._load_versions(uuid)
        self._log.debug('unlocked vault "{}" ({})', uuid, self.vaults[uuid]['name'])
        self.raise_event('VaultUnlocked', self.vaults[uuid])

    def lock_vault(self, uuid):
        """Lock a vault.
        
        This destroys the decrypted private keys and any decrypted items that
        are cached. It is not an error to lock a vault that is already locked.
        """
        if uuid not in self.vaults:
            raise NotFound('No such vault: {0}'.format(uuid))
        assert uuid in self._private_keys
        if len(self._private_keys[uuid]) == 0:
            return
        self._private_keys[uuid] = []
        self._clear_version_cache(uuid)
        self._log.debug('locked vault "{}" ({})', uuid, self.vaults[uuid]['name'])
        self.raise_event('VaultLocked', self.vaults[uuid])

    def vault_is_locked(self, uuid):
        """Return whether a vault is locked."""
        if uuid not in self.vaults:
            raise NotFound('No such vault: {0}'.format(uuid))
        assert uuid in self._private_keys
        return len(self._private_keys[uuid]) == 0

    # Versions

    def get_version(self, vault, uuid):
        """Get a single current version."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        assert vault in self._private_keys
        if len(self._private_keys[vault]) == 0:
            raise VaultLocked('Vault {0} is locked'.format(vault))
        assert vault in self._version_cache
        item = self._version_cache[vault].get(uuid)
        version = self._get_version(item) if item else None
        return version

    def get_versions(self, vault):
        """Return a list of all current versions."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        assert vault in self._private_keys
        if len(self._private_keys[vault]) == 0:
            raise VaultLocked('Vault {0} is locked'.format(vault))
        assert vault in self._version_cache
        versions = []
        for item in self._version_cache[vault].values():
            version = self._get_version(item)
            versions.append(version)
        return versions

    def add_version(self, vault, version):
        """Add a new version."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        assert vault in self._private_keys
        if len(self._private_keys[vault]) == 0:
            raise VaultLocked('Vault {0} is locked'.format(vault))
        assert vault in self._version_cache
        version['id'] = crypto.random_uuid()
        item = self._new_version(vault, version)
        self._encrypt_item(vault, item)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        self.import_item(vault, item)
        version = self._get_version(item)
        return version

    def replace_version(self, vault, version):
        """Update an existing version."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        assert vault in self._private_keys
        if len(self._private_keys[vault]) == 0:
            raise VaultLocked('Vault {0} is locked'.format(vault))
        assert vault in self._version_cache
        uuid = version['id']
        if uuid not in self._version_cache[vault]:
            raise NotFound('No such version: {0}'.format(uuid))
        parent = self._version_cache[vault][uuid]['payload']['id']
        item = self._new_version(vault, version, parent=parent)
        self._encrypt_item(vault, item)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        self.import_item(vault, item)
        version = self._get_version(item)
        return version

    def delete_version(self, vault, version):
        """Delete a version."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        assert vault in self._private_keys
        if len(self._private_keys[vault]) == 0:
            raise VaultLocked('Vault {0} is locked'.format(vault))
        assert vault in self._version_cache
        uuid = version['id']
        if uuid not in self._version_cache[vault]:
            raise NotFound('No such version: {0}'.format(uuid))
        parent = self._version_cache[vault][uuid]['payload']['id']
        # XXX: revisit payload of item
        item = self._new_version(vault, version, parent=parent)
        item['payload']['deleted'] = True
        self._encrypt_item(vault, item)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        self.import_item(vault, item)
        version = self._get_version(item)
        return version

    def get_version_history(self, vault, uuid):
        """Return the history for version `uuid`."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        assert vault in self._private_keys
        if len(self._private_keys[vault]) == 0:
            raise VaultLocked('Vault {0} is locked'.format(vault))
        assert vault in self._linear_history
        if uuid not in self._linear_history[vault]:
            raise NotFound('No such version: {0}'.format(uuid))
        history = [ self._get_version(item)
                    for item in self._linear_history[vault][uuid] ]
        return history

    def get_version_item(self, vault, uuid):
        """Get the most recent item for a version (including
        deleted versions)."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        assert vault in self._private_keys
        if len(self._private_keys[vault]) == 0:
            raise VaultLocked('Vault {0} is locked'.format(vault))
        assert vault in self._version_cache
        version = self._linear_history[vault].get(uuid)
        if version:
            version = version[0].copy()
        return version

    # Pairing

    def get_certificate(self, vault, node):
        """Return a certificate for `node` in `vault`, if there is one."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        if node not in self._trusted_certs[vault]:
            return
        return self._trusted_certs[vault][node][0]

    def get_auth_key(self, vault):
        """Return the private authentication key for `vault`."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        vault = self.vaults[vault]
        key = base64.decode(vault['keys']['auth']['private'])
        return key

    def add_certificate(self, vault, certinfo):
        """Add a certificate to a vault.

        Adding a certificate to a vault establishes a trust relationship
        between this node and the node that we are generating the certifcate
        for. If the certificate is "synconly", then only synchronization with
        us is allowed. If the certificate is not synconly, in addition,
        existing versions will be re-encrypted to the newly added node, and new
        versions will be encrypted to it automatically. The new node may also
        introduce other new nodes into the vault. 
        """
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        assert vault in self._private_keys
        if len(self._private_keys[vault]) == 0:
            raise VaultLocked('Vault {0} is locked'.format(vault))
        vres = va_certinfo.validate(certinfo)
        if not vres:
            raise ValidationError('Invalid certificate: {0}'.format(vres.error))
        item = self._new_certificate(vault, **certinfo)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        self.import_item(vault, item)
        synconly = certinfo.get('restrictions', {}).get('synconly')
        if not synconly:
            for version in self.get_versions(vault):
                if not version.get('deleted'):
                    self.replace_version(vault, version)
        return item

    # Synchronization

    def get_vector(self, vault):
        """Return a vector containing the latest versions for each node that
        we know of."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        vector = self.store.execute('items', """
                    SELECT $origin$node,MAX($origin$seqnr)
                    FROM items
                    WHERE $vault = ?
                    GROUP BY $origin$node""", (vault,))
        return vector

    def get_items(self, vault, vector=None):
        """Return the items in `vault` that are newer than `vector`."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        if vector is not None:
            if not isinstance(vector, (tuple, list)):
                raise ModelError('Illegal vector')
            for elem in vector:
                if not isinstance(elem, (tuple, list)) or len(elem) != 2 or \
                        not isinstance(elem[0], compat.string_types) or \
                        not isinstance(elem[1], compat.integer_types):
                    raise ModelError('Illegal vector')
        query = '$vault = ?'
        args = [vault]
        if vector is not None:
            nodes = self.store.execute('items',
                            'SELECT DISTINCT $origin$node FROM items')
            terms = []
            vector = dict(vector)
            for node, in nodes:
                if node in vector:
                    terms.append('($origin$node = ? AND $origin$seqnr > ?)')
                    args.append(node); args.append(vector[node])
                else:
                    terms.append('$origin$node = ?')
                    args.append(node)
            query += ' AND (%s)' % ' OR '.join(terms)
        return self.store.findall('items', query, args)

    def import_item(self, vault, item, notify=True):
        """Import a single item."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        vres = va_item.validate(item)
        if not vres:
            raise ValidationError('Invalid item: {0}'.format(vres.error))
        ptype = item['payload']['type']
        if ptype == 'Certificate':
            vres = va_cert.validate(item)
            if not vres:
                raise ValidationError('Invalid certificate: {0}'.format(vres.error))
            self.store.insert('items', item)
            self._log.debug('imported certificate, re-calculating trust')
            self._calculate_trust(item['vault'])
            # Find items that are signed by this certificate
            query = "$vault = ? AND $payload$type = 'EncryptedItem'" \
                    " AND $origin$node = ?"
            args = (vault, item['payload']['node'])
            items = self.store.findall('items', query, args)
        elif ptype == 'EncryptedItem':
            vres = va_encitem.validate(item)
            if not vres:
                raise ValidationError('Invalid encrypted item: {0}'.format(vres.error))
            self.store.insert('items', item)
            items = [item]
        else:
            raise ValidationError('Unknown payload type: {0}'.format(ptype))
        assert vault in self._private_keys
        if len(self._private_keys[vault]) == 0:
            return
        # See if the wider set of certificates exposed some versions
        versions = []
        for item in items:
            if not self._verify_item(vault, item) or \
                    not self._decrypt_item(vault, item) or \
                    not va_decitem.match(item) or \
                    not va_version.match(item):
                continue
            versions.append(item)
        self._log.debug('updating version cache for {} versions', len(versions))
        self._update_version_cache(versions, notify=notify)

    def import_items(self, vault, items, notify=True):
        """Import multiple items. This is more efficient than calling
        import_item() multiple times. Items with errors are silently skipped
        and do not prevent good items to be imported."""
        if vault not in self.vaults:
            raise NotFound('No such vault: {0}'.format(vault))
        self._log.debug('importing {} items', len(items))
        items = [ item for item in items if va_item.match(item) ]
        self._log.debug('{} items are well formed', len(items))
        # Weed out items we already have.
        vector = dict(self.get_vector(vault))
        items = [ item for item in items
                  if item['origin']['seqnr']
                        > vector.get(item['origin']['node'], -1) ]
        self._log.debug('{} items are new', len(items))
        # If we are adding certs we need to add them first and re-calculate
        # trust before adding the other items.
        certs = [ item for item in items
                  if item['payload']['type'] == 'Certificate'
                        and va_cert.match(item) ]
        if certs:
            # It is safe to import any certificate. Certificates require
            # a trusted signature before they are considered trusted.
            with self.store.begin():
                for item in certs:
                    self.store.insert('items', item)
            self._calculate_trust(vault)
            self._log.debug('imported {} certificates and recalculated trust', len(certs))
            # Some items may have become exposed by the certs. Find items
            # that were signed by the certs we just added.
            query = "$vault = ? AND $payload$type = 'EncryptedItem'"
            query += ' AND (%s)' % ' OR '.join([ '$origin$node = ?' ] * len(certs))
            args = [ vault ]
            args += [ cert['payload']['node'] for cert in certs ]
            certitems = self.store.findall('items', query, args)
            self._log.debug('{} items are possibly touched by these certs', len(certitems))
        else:
            certitems = []
        # Now see which items are valid under the possibly wider set of
        # certificates and add them
        encitems = [ item for item in items
                     if item['payload']['type'] == 'EncryptedItem'
                            and va_encitem.match(item) ]
        with self.store.begin():
            for item in encitems:
                self.store.insert('items', item)
        self._log.debug('imported {} encrypted items', len(encitems))
        # Update version and history caches (if the vault is unlocked)
        assert vault in self._private_keys
        if len(self._private_keys[vault]) > 0:
            versions = []
            for item in itertools.chain(encitems, certitems):
                if not self._verify_item(vault, item) or \
                        not self._decrypt_item(vault, item) or \
                        not va_decitem.match(item) or \
                        not va_version.match(item):
                    continue
                versions.append(item)
            self._update_version_cache(versions, notify=notify)
        return len(certs) + len(encitems)
