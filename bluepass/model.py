#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import time
import math
import itertools
import socket
import uuid

from bluepass import base64, json, uuid4, logging
from bluepass.error import StructuredError
from bluepass.crypto import CryptoProvider, CryptoError
from bluepass import platform

import hashlib

import gruvi
from gruvi import compat

__all__ = ('Model', 'ModelError')


class ModelError(StructuredError):
    """Model error."""


class Model(object):
    """This class implements our vault/item model on top of our database."""

    def __init__(self, database):
        """Create a new model on top of `database`."""
        self.database = database
        self.crypto = CryptoProvider()
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
        self._load_vaults()

    def _update_schema(self):
        """Create or update the database schema."""
        db = self.database
        if 'config' not in db.tables:
            db.create_table('config')
        if 'vaults' not in db.tables:
            db.create_table('vaults')
            db.create_index('vaults', '$id', 'TEXT', True)
        if 'items' not in db.tables:
            db.create_table('items')
            db.create_index('items', '$id', 'TEXT', True)
            db.create_index('items', '$vault', 'TEXT', False)
            db.create_index('items', '$origin$node', 'TEXT', False)
            db.create_index('items', '$origin$seqnr', 'INT', False)
            db.create_index('items', '$payload$_type', 'TEXT', False)

    def check_vault(self, vault):
        """Check a vault for consistency."""
        try:
            u = json.unpack(vault, '{s:s,s:s,s:s,s:' \
                            '{s:{s:s,s:s,s:s,s:{s:s,s:s,s:s,s:s,s:u,s:u},' \
                            '    s:{s:s,s:s,s:s}},'
                            ' s:{s:s,s:s,s:s,s:{s:s,s:s,s:s,s:s,s:u,s:u},' \
                            '    s:{s:s,s:s,s:s}},'
                            ' s:{s:s,s:s,s:s,s:{s:s}}}}',
                            ('id', 'name', 'node', 'keys',
                             'sign', 'keytype', 'private', 'public', 'encinfo',
                                'algo', 'iv', 'kdf', 'salt', 'count', 'length',
                                'pwcheck', 'algo', 'random', 'verifier',
                             'encrypt', 'keytype', 'private', 'public', 'encinfo',
                                'algo', 'iv', 'kdf', 'salt', 'count', 'length',
                                'pwcheck', 'algo', 'random', 'verifier',
                             'auth', 'keytype', 'private', 'public', 'encinfo',
                                'algo'))
        except json.UnpackError as e:
            return False, str(e)
        if not uuid4.check(u[0]):
            return False, 'Illegal UUID "%s"' % u[0]
        if len(u[1]) == 0:
            return False, 'Vault name cannot be empty'
        elif len(u[1]) > 100:
            return False, 'Vault name too long (max = 100 characters)'
        if not uuid4.check(u[2]):
            return False, 'Illegal node UUID "%s"' % u[2]
        if u[3] != 'rsa':
            return False, 'Unknown key type "%s" for sign key' % u[3]
        if not base64.check(u[4]):
            return False, 'Invalid base64 for private sign key'
        if not base64.check(u[5]):
            return False, 'Invalid base64 for public sign key'
        if u[6] != 'aes-cbc-pkcs7':
            return False, 'Unkown algo "%s" for sign key' % u[6]
        if not base64.check(u[7]):
            return False, 'Invalid base64 for encinfo/IV for sign key' % u[7]
        if u[8] not in ('pbkdf2-hmac-sha1', 'pbkdf2-hmac-sha256'):
            return False, 'Unknown encinfo/kdf "%s" for sign key' % u[8]
        if not base64.check(u[9]):
            return False, 'Invalid base64 for encinfo/salt for sign key' % u[9]
        if u[12] != 'hmac-random-sha256':
            return False, 'Unknown pwcheck/algo "%s" for sign key' % u[12]
        if not base64.check(u[13]):
            return False, 'Invalid base64 in pwcheck/random for sign key' % u[13]
        if not base64.check(u[14]):
            return False, 'Invalid base64 in pwcheck/verifier for sign key' % u[14]
        if u[15] != 'rsa':
            return False, 'Unknown key type "%s" for encrypt key' % u[15]
        if not base64.check(u[16]):
            return False, 'Invalid base64 for private encrypt key'
        if not base64.check(u[17]):
            return False, 'Invalid base64 for public encrypt key'
        if u[18] != 'aes-cbc-pkcs7':
            return False, 'Unkown algo "%s" for encrypt key' % u[18]
        if not base64.check(u[19]):
            return False, 'Invalid base64 for encinfo/IV for encrypt key' % u[19]
        if u[20] not in ('pbkdf2-hmac-sha1', 'pbkdf2-hmac-sha256'):
            return False, 'Unknown encinfo/kdf "%s" for encrypt key' % u[20]
        if not base64.check(u[21]):
            return False, 'Invalid base64 for encinfo/salt for encrypt key' % u[21]
        if u[24] != 'hmac-random-sha256':
            return False, 'Unknown pwcheck/algo "%s" for encrypt key' % u[24]
        if not base64.check(u[25]):
            return False, 'Invalid base64 in pwcheck/random for encrypt key' % u[25]
        if not base64.check(u[26]):
            return False, 'Invalid base64 in pwcheck/verifier for encrypt key' % u[26]
        if u[27] != 'rsa':
            return False, 'Unknown key type "%s" for auth key' % u[27]
        if not base64.check(u[28]):
            return False, 'Invalid base64 for private auth key'
        if not base64.check(u[29]):
            return False, 'Invalid base64 for public auth key'
        if u[30] != 'plain':
            return False, 'Unexpected algo "%s" for encrypt key' % u[30]
        return True, 'All checks passed'

    def check_item(self, item):
        """Check the envelope of an item."""
        try:
            u = json.unpack(item, '{s:s,s:s,s:s,s:{s:s,s:u!},' \
                            's:{s:s*},s:{s:s,s:s!}!}',
                            ('id', '_type', 'vault', 'origin', 'node', 'seqnr',
                             'payload', '_type', 'signature', 'algo', 'blob'))
        except json.UnpackError as e:
            return False, str(e)
        if not uuid4.check(u[0]):
            return False, 'Illegal UUID'
        if u[1] != 'Item':
            return False, 'Expecting type "Item" (got: "%s")' % u[1]
        if not uuid4.check(u[2]):
            return False, 'Illegal vault UUID'
        if not uuid4.check(u[3]):
            return False, 'Illegal origin node UUID'
        if u[5] not in ('Certificate', 'EncryptedItem'):
            return False, 'Unknown payload type "%s"' % u[5]
        if u[6] != 'rsa-pss-sha256':
            return False, 'Unkown signature algo "%s"' % u[6]
        if not base64.check(u[7]):
            return False, 'Illegal base64 for signature'
        return True, 'All checks passed'

    def check_certificate(self, item):
        """Check the format of a certificiate.

        NOTE: This only does format checks , no signatures are verified!
        """
        try:
            u = json.unpack(item, '{s:s,s:{s:s,s:s,s:s,s:s,s:{s?:{s:s,s:s!},' \
                            's?:{s:s,s:s!},s:{s:s,s:s!}!},s?:{s?:b!}!}}',
                            ('id', 'payload', 'id', '_type', 'node', 'name',
                             'keys', 'sign', 'key', 'keytype',
                             'encrypt', 'key', 'keytype', 'auth', 'key',
                             'keytype', 'restrictions', 'synconly'))
        except json.UnpackError as e:
            return False, str(e)
        assert uuid4.check(u[0])
        if not uuid4.check(u[1]):
            return False, 'Invalid UUID'
        if u[2] != 'Certificate':
            return False, 'Expecting type "Certificate" (got: "%s")' % u[3]
        if not uuid4.check(u[3]):
            return False, 'Invalid node UUID'
        if not u[4]:
            return False, 'Name cannot be empty'
        elif len(u[4]) > 100:
            return False, 'Name too long (max = 100 characters)'
        if not base64.check(u[5]):
            return False, 'Invalid base64 for sign key'
        if u[6] != 'rsa':
            return False, 'Unknown key type "%s" for sign key' % u[6]
        if not base64.check(u[7]):
            return False, 'Invalid base64 for encrypt key'
        if u[8] != 'rsa':
            return False, 'Unkown key type "%s" for encrypt key' % u[8]
        if not base64.check(u[9]):
            return False, 'Invalid base64 for auth key'
        if u[10] != 'rsa':
            return False, 'Unkown key type "%s" for auth key' % u[10]
        return True, 'All checks passed'

    def check_encrypted_item(self, item):
        """Check the format of an encrypted item."""
        try:
            u = json.unpack(item, '{s:s,s:{s:s,s:s,s:s,s:s,s:s,s:o!}}',
                            ('id', 'payload', '_type', 'algo', 'iv',
                             'blob', 'keyalgo', 'keys'))
        except json.UnpackError as e:
            return False, str(e)
        assert uuid4.check(u[0])
        assert u[1] == 'EncryptedItem'
        if u[2] != 'aes-cbc-pkcs7':
            return False, 'Unknown algo "%s"' % u[2]
        if not base64.check(u[3]):
            return False, 'Invalid base64 for IV'
        if not base64.check(u[4]):
            return False, 'Invalid base64 for blob'
        if u[5] != 'rsa-oaep':
            return False, 'Unknown keyalgo "%s"' % u[5]
        if not isinstance(u[6], dict):
            return False, 'Invalid keys dict'
        for key,value in u[6].items():
            if not uuid4.check(key):
                return False, 'Illegal key UUID "%s" in keys dict' % key
            if not base64.check(value):
                return False, 'Invalid base64 for key "%s" in keys dict' % key
        return True, 'All checks passed'

    def _check_items(self, vault):
        """Check all items in a vault."""
        total = errors = 0
        items = self.database.findall('items', '$vault = ?', (vault,))
        self._log.debug('Checking all items in vault "{}"', vault)
        for item in items:
            uuid = item.get('id', '<no id>')
            status, detail = self.check_item(item)
            if not status:
                self._log.error('Invalid item "{}": {}', uuid, detail)
                errors += 1
                continue
            typ = item['payload']['_type']
            if typ == 'Certificate':
                status, detail = self.check_certificate(item)
                if not status:
                    self._log.error('Invalid certificate "{}": {}', uuid, detail)
                    errors += 1
                    continue
            elif typ == 'EncryptedItem':
                status, detail = self.check_encrypted_item(item)
                if not status:
                    self._log.error('Invalid encrypted item "{}": {}', uuid, detail)
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
        status, detail = self.check_vault(vault)
        if not status:
            self._log.error('Vault "{}" has errors (skipping): {}', uuid, detail)
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
        seqnr = self.database.execute('items', """
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
        filename = self.database.filename
        self._log.debug('loading all vaults from database {}', filename)
        vaults = self.database.findall('vaults')
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
        assert self.check_item(item)[0]
        signature = item.pop('signature')
        if signature['algo'] != 'rsa-pss-sha256':
            self._log.error('unknown signature algo "{}" for item "{}"', algo, item['id'])
            return False
        message = json.dumps_c14n(item).encode('utf8')
        blob = base64.decode(signature['blob'])
        try:
            status = self.crypto.rsa_verify(message, blob, pubkey, 'pss-sha256')
        except CryptoError:
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
        query = "$vault = ? AND $payload$_type = 'Certificate'"
        result = self.database.findall('items', query, (vault,))
        for cert in result:
            assert self.check_item(cert)[0]
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

    def check_decrypted_item(self, item):
        """Check a decrypted item."""
        try:
            u = json.unpack(item, '{s:s,s:{s:s,s:s}}',
                            ('id', 'payload', 'id', '_type'))
        except json.UnpackError as e:
            return False, str(e)
        if not uuid4.check(u[1]):
            return False, 'Invalid UUID "%s"' % u[1]
        if u[2] != 'Version':
            return False, 'Unknown type "%s"' % u[2]
        return True, 'All checks passed'

    def check_version(self, item):
        """Check a decrypted item and ensure it is a valid version."""
        try:
            u = json.unpack(item, '{s:s,s:{s:s,s:s,s?:s,s?:b,s:u,s{s:s}}}',
                            ('id', 'payload', 'id', '_type', 'parent', 'deleted',
                             'created_at', 'version', 'id'))
        except json.UnpackError as e:
            return str(e)
        assert uuid4.check(u[0])
        if not uuid4.check(u[1]):
            return False, 'Invalid version UUID "%s"' % u[1]
        if u[2] != 'Version':
            return False, 'Expecting type "Version" (got: "%s")' % u[2]
        if u[3] and not uuid4.check(u[3]):
            return False, 'Invalid parent UUID "%s"' % u[3]
        if not uuid4.check(u[6]):
            return False, 'Invalid version data UUID "%s"' % u[6]
        return True, 'All checks passed'

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
        query = "$vault = ? AND $payload$_type = 'EncryptedItem'"
        items = self.database.findall('items', query, (vault,))
        for item in items:
            if not self._verify_item(vault, item) or \
                    not self._decrypt_item(vault, item) or \
                    not self.check_decrypted_item(item)[0] or \
                    not self.check_version(item)[0]:
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
        blob = self.crypto.rsa_sign(message, signkey, padding='pss-sha256')
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
        crypto = self.crypto
        clear = item.pop('payload')
        item['payload'] = payload = {}
        payload['_type'] = 'EncryptedItem'
        payload['algo'] = 'aes-cbc-pkcs7'
        iv = crypto.random(16)
        payload['iv'] = base64.encode(iv)
        symkey = crypto.random(16)
        message = json.dumps(clear).encode('utf8')
        blob = crypto.aes_encrypt(message, symkey, iv, mode='cbc-pkcs7')
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
            enckey = crypto.rsa_encrypt(symkey, pubkey, padding='oaep')
            keys[node] = base64.encode(enckey)

    def _decrypt_item(self, vault, item):
        """INTERNAL: decrypt an encrypted item."""
        assert vault in self.vaults
        assert vault in self._private_keys
        crypto = self.crypto
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
            symkey = crypto.rsa_decrypt(enckey, privkey, padding='oaep')
            blob = base64.decode(item['payload']['blob'])
            iv = base64.decode(item['payload']['iv'])
            clear = crypto.aes_decrypt(blob, symkey, iv, mode='cbc-pkcs7')
        except CryptoError as e:
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
        item['id'] = self.crypto.randuuid()
        item['_type'] = 'Item'
        item['vault'] = vault
        item['payload'] = payload = {}
        payload['_type'] = ptype
        payload.update(kwargs)
        return item

    def _new_certificate(self, vault, **kwargs):
        """Create anew certificate."""
        item = self._new_item(vault, 'Certificate', **kwargs)
        item['payload']['id'] = self.crypto.randuuid()
        return item

    def _new_version(self, vault, parent=None, **version):
        """Create a new empty version."""
        item = self._new_item(vault, 'Version')
        payload = item['payload']
        payload['id'] = self.crypto.randuuid()
        payload['created_at'] = int(time.time())
        if parent is not None:
            payload['parent'] = parent
        payload['version'] = version.copy()
        return item

    def _get_version(self, item):
        """Return the version inside an item, with envelope."""
        payload = item['payload'].copy()
        version = payload['version'].copy()
        del payload['version']
        version['_envelope'] = payload
        return version

    def _create_vault_key(self, password):
        """Create a new vault key. Return a tuple (private, public,
        keyinfo). The keyinfo structure contains the encrypted keys."""
        crypto = self.crypto
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
        iv = crypto.random(16)
        encinfo['iv'] = base64.encode(iv)
        prf = 'hmac-sha256' if self.crypto.pbkdf2_prf_available('hmac-sha256') \
                    else 'hmac-sha1'
        encinfo['kdf'] = 'pbkdf2-%s' % prf
        # Tune pbkdf2 so that it takes about 0.2 seconds (but always at
        # least 4096 iterations).
        count = max(4096, int(0.2 * crypto.pbkdf2_speed(prf)))
        self._log.debug('using {} iterations for PBKDF2', count)
        encinfo['count'] = count
        encinfo['length'] = 16
        salt = crypto.random(16)
        encinfo['salt'] = base64.encode(salt)
        symkey = crypto.pbkdf2(password, salt, encinfo['count'],
                               encinfo['length'], prf=prf)
        enckey = crypto.aes_encrypt(private, symkey, iv, mode='cbc-pkcs7')
        keyinfo['private'] = base64.encode(enckey)
        keyinfo['pwcheck'] = pwcheck = {}
        pwcheck['algo'] = 'hmac-random-sha256'
        random = crypto.random(16)
        pwcheck['random'] = base64.encode(random)
        verifier = crypto.hmac(symkey, random, 'sha256')
        pwcheck['verifier'] = base64.encode(verifier)
        return private, public, keyinfo

    def _create_vault_keys(self, password):
        """Create all 3 vault keys (sign, encrypt and auth)."""
        # Generate keys in the CPU thread pool.
        prf = 'hmac-sha256' if self.crypto.pbkdf2_prf_available('hmac-sha256') \
                    else 'hmac-sha1'
        dummy = self.crypto.pbkdf2_speed(prf)
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

    def get_config(self):
        """Return the configuration document."""
        config = self.database.findone('config')
        if config is None:
            config = { 'id': self.crypto.randuuid() }
            self.database.insert('config', config)
        return config

    def update_config(self, config):
        """Update the configuration document."""
        if not isinstance(config, dict):
            raise ModelError('InvalidArgument', '"config" must be a dict')
        uuid = config.get('id')
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Invalid config uuid')
        self.database.update('config', '$id = ?', (uuid,), config)

    def create_vault(self, name, password, uuid=None, notify=True):
        """Create a new vault.
        
        The `name` argument specifies the name of the vault to create. The
        private keys for this vault are encrypted with `password'. If the
        `uuid` argument is given, a vault with this UUID is created. The
        default is to generate an new UUID for this vault. The `notify`
        arguments determines wether or not callbacks must be called when this
        vault is created.
        """
        if not isinstance(name, compat.string_types):
            raise ModelError('InvalidArgument', '"name" must be str/unicode')
        if not isinstance(password, compat.string_types):
            raise ModelError('InvalidArgument', '"password" must be str/unicode')
        if uuid is not None:
            if not uuid4.check(uuid):
                raise ModelError('InvalidArgument', 'Illegal vault uuid')
            if uuid in self.vaults:
                raise ModelError('Exists', 'A vault with this UUID already exists')
        if isinstance(password, compat.text_type):
            password = password.encode('utf8')
        vault = {}
        if uuid is None:
            uuid = self.crypto.randuuid()
        vault['id'] = uuid
        vault['_type'] = 'Vault'
        vault['name'] = name
        vault['node'] = self.crypto.randuuid()
        keys = self._create_vault_keys(password)
        vault['keys'] = dict(((key, keys[key][2]) for key in keys))
        self.database.insert('vaults', vault)
        if notify:
            self.raise_event('VaultAdded', vault)
        self.vaults[uuid] = vault
        # Start unlocked by default
        self._private_keys[uuid] = (keys['sign'][0], keys['encrypt'][0])
        self._version_cache[uuid] = {}
        self._linear_history[uuid] = {}
        self._full_history[uuid] = {}
        self._next_seqnr[uuid] = 0
        # Add a self-signed certificate
        certinfo = { 'node': vault['node'], 'name': socket.gethostname() }
        keys = certinfo['keys'] = {}
        for key in vault['keys']:
            keys[key] = { 'key': vault['keys'][key]['public'],
                          'keytype': vault['keys'][key]['keytype'] }
        certinfo['restrictions'] = {}
        item = self._new_certificate(uuid, **certinfo)
        self._add_origin(uuid, item)
        self._sign_item(uuid, item)
        self.import_item(uuid, item, notify=notify)
        return vault

    def get_vault(self, uuid):
        """Return the vault with `uuid` or None if there is no such vault."""
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        return self.database.findone('vaults', '$id = ?', (uuid,))

    def get_vaults(self):
        """Return a list of all vaults."""
        return self.database.findall('vaults')

    def update_vault(self, vault):
        """Update a vault."""
        status, detail = self.check_vault(vault)
        if not status:
            raise ModelError('InvalidArgument', 'Invalid vault: %s' % detail)
        self.database.update('vaults', '$id = ?', (vault['id'],), vault)
        self.raise_event('VaultUpdated', vault)

    def delete_vault(self, vault):
        """Delete a vault and all its items."""
        if not isinstance(vault, dict):
            raise ModelError('InvalidArgument', '"vault" must be a dict')
        uuid = vault.get('id')
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Invalid vault UUID')
        if uuid not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        self.database.delete('vaults', '$id = ?', (uuid,))
        self.database.delete('items', '$vault = ?', (uuid,))
        # The VACUUM command here ensures that the data we just deleted is
        # removed from the sqlite database file. However, quite likely the
        # data is still on the disk, at least for some time. So this is not
        # a secure delete.
        self.database.execute('vaults', 'VACUUM')
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
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if uuid not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        stats = {}
        stats['current_versions'] = len(self._version_cache[uuid])
        stats['total_versions'] = len(self._linear_history[uuid])
        linsize = sum((len(h) for h in self._linear_history[uuid].items()))
        stats['linear_history_size'] = linsize
        fullsize = sum((len(h) for h in self._full_history[uuid].items()))
        stats['full_history_size'] = fullsize
        result = self.database.execute('items', """
                    SELECT COUNT(*) FROM items WHERE $vault = ?
                    """, (uuid,))
        stats['total_items'] = result[0]
        result = self.database.execute('items', """
                    SELECT COUNT(*) FROM items WHERE $vault = ?
                    AND $payload$_type = 'Certificate'
                    """, (uuid,))
        stats['total_certificates'] = result[0]
        result = self.database.execute('items', """
                    SELECT COUNT(*) FROM
                    (SELECT DISTINCT $payload$node FROM items
                     WHERE $vault = ? AND $payload$_type = 'Certificate')
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
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if not isinstance(password, compat.string_types):
            raise ModelError('InvalidArgument', 'Illegal password')
        if uuid not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        assert uuid in self._private_keys
        if len(self._private_keys[uuid]) > 0:
            return
        if isinstance(password, compat.text_type):
            password = password.encode('utf8')
        crypto = self.crypto
        for key in ('sign', 'encrypt'):
            keyinfo = self.vaults[uuid]['keys'][key]
            pubkey = base64.decode(keyinfo['public'])
            privkey = base64.decode(keyinfo['private'])
            encinfo = keyinfo['encinfo']
            pwcheck = keyinfo['pwcheck']
            # These are enforced by check_vault()
            assert encinfo['algo'] == 'aes-cbc-pkcs7'
            assert encinfo['kdf'] in ('pbkdf2-hmac-sha1', 'pbkdf2-hmac-sha256')
            assert pwcheck['algo'] == 'hmac-random-sha256'
            salt = base64.decode(encinfo['salt'])
            iv = base64.decode(encinfo['iv'])
            prf = encinfo['kdf'][7:]
            symkey = crypto.pbkdf2(password, salt, encinfo['count'],
                                   encinfo['length'], prf=prf)
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
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if uuid not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        assert uuid in self._private_keys
        if len(self._private_keys[uuid]) == 0:
            return
        self._private_keys[uuid] = []
        self._clear_version_cache(uuid)
        self._log.debug('locked vault "{}" ({})', uuid, self.vaults[uuid]['name'])
        self.raise_event('VaultLocked', self.vaults[uuid])

    def vault_is_locked(self, uuid):
        """Return whether a vault is locked."""
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if uuid not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        assert uuid in self._private_keys
        return len(self._private_keys[uuid]) == 0

    def get_version(self, vault, uuid):
        """Get a single current version."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Illegal version uuid')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        if self.vault_is_locked(vault):
            raise ModelError('Locked', 'Vault is locked')
        assert vault in self._version_cache
        item = self._version_cache[vault].get(uuid)
        version = self._get_version(item) if item else None
        return version

    def get_versions(self, vault):
        """Return a list of all current versions."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        if self.vault_is_locked(vault):
            raise ModelError('Locked', 'Vault is locked')
        assert vault in self._version_cache
        versions = []
        for item in self._version_cache[vault].values():
            version = self._get_version(item)
            versions.append(version)
        return versions

    def add_version(self, vault, version):
        """Add a new version."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if not isinstance(version, dict):
            raise ModelError('InvalidArgument', '"version" must be a dict')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        if vault not in self._private_keys:
            raise ModelError('Locked', 'Vault is locked')
        version['id'] = self.crypto.randuuid()
        item = self._new_version(vault, **version)
        self._encrypt_item(vault, item)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        self.import_item(vault, item)
        version = self._get_version(item)
        return version

    def update_version(self, vault, version):
        """Update an existing version."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if not isinstance(version, dict):
            raise ModelError('InvalidArgument', '"version" must be a dict')
        uuid = version.get('id')
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Invalid version uuid')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        if vault not in self._private_keys:
            raise ModelError('Locked', 'Vault is locked')
        assert vault in self._version_cache
        if uuid not in self._version_cache[vault]:
            raise ModelError('NotFound', 'Version to update not found')
        parent = self._version_cache[vault][uuid]['payload']['id']
        item = self._new_version(vault, parent=parent, **version)
        self._encrypt_item(vault, item)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        self.import_item(vault, item)
        version = self._get_version(item)
        return version

    def delete_version(self, vault, version):
        """Delete a version."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if not isinstance(version, dict):
            raise ModelError('InvalidArgument', '"version" must be a dict')
        uuid = version.get('id')
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Invalid version uuid')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        if vault not in self._private_keys:
            raise ModelError('Locked', 'Vault is locked')
        assert vault in self._version_cache
        if uuid not in self._version_cache[vault]:
            raise ModelError('NotFound', 'Version to delete not found')
        parent = self._version_cache[vault][uuid]['payload']['id']
        item = self._new_version(vault, parent=parent, **version)
        item['payload']['deleted'] = True
        self._encrypt_item(vault, item)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        self.import_item(vault, item)
        version = self._get_version(item)
        return version

    def get_version_history(self, vault, uuid):
        """Return the history for version `uuid`."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Illegal version uuid')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        if self.vault_is_locked(vault):
            raise ModelError('Locked', 'Vault is locked')
        assert vault in self._linear_history
        if uuid not in self._linear_history[vault]:
            raise ModelError('NotFound', 'Version not found')
        history = [ self._get_version(item)
                    for item in self._linear_history[vault][uuid] ]
        return history

    def get_version_item(self, vault, uuid):
        """Get the most recent item for a version (including
        deleted versions)."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if not uuid4.check(uuid):
            raise ModelError('InvalidArgument', 'Illegal version uuid')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        if self.vault_is_locked(vault):
            raise ModelError('Locked', 'Vault is locked')
        assert vault in self._version_cache
        version = self._linear_history[vault].get(uuid)
        if version:
            version = version[0].copy()
        return version

    # Pairing

    def get_certificate(self, vault, node):
        """Return a certificate for `node` in `vault`, if there is one."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if not uuid4.check(node):
            raise ModelError('InvalidArgument', 'Illegal node uuid')
        if vault not in self.vaults or node not in self._trusted_certs[vault]:
            return
        return self._trusted_certs[vault][node][0]

    def get_auth_key(self, vault):
        """Return the private authentication key for `vault`."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        vault = self.vaults[vault]
        key = base64.decode(vault['keys']['auth']['private'])
        return key

    def check_certinfo(self, certinfo):
        """Check a certificate info structure."""
        try:
            u = json.unpack(certinfo, '{s:s,s:s,s:{s:{s:s,s:s!},' \
                            's:{s:s,s:s!},s:{s:s,s:s!}!},s?:{s?:b!}!}',
                            ('node', 'name', 'keys', 'sign', 'key', 'keytype',
                             'encrypt', 'key', 'keytype', 'auth', 'key',
                             'keytype', 'restrictions', 'synconly'))
        except json.UnpackError as e:
            return False, str(e)
        if not uuid4.check(u[0]):
            return False, 'Illegal node UUID'
        if not u[1]:
            return False, 'Name must be > 0 characters'
        if len(u[1]) > 100:
            return False, 'Name too long (max = 100 characters)'
        if not base64.check(u[2]):
            return False, 'Illegal base64 in sign key'
        if u[3] != 'rsa':
            return False, 'Unknown sign key type: %s' % u[3]
        if not base64.check(u[4]):
            return False, 'Illegal base64 in encrypt key'
        if u[5] != 'rsa':
            return False, 'Unknown encrypt key type: %s' % u[5]
        if not base64.check(u[6]):
            return False, 'Illegal base64 in auth key'
        if u[7] != 'rsa':
            return False, 'Unknown auth key type: %s' % u[5]
        return True, 'All checks passed'

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
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault UUID')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'Vault not found')
        if self.vault_is_locked(vault):
            raise ModelError('Locked', 'Vault is locked')
        status, detail = self.check_certinfo(certinfo)
        if not status:
            raise ModelError('InvalidArgument', detail)
        item = self._new_certificate(vault, **certinfo)
        self._add_origin(vault, item)
        self._sign_item(vault, item)
        self.import_item(vault, item)
        synconly = certinfo.get('restrictions', {}).get('synconly')
        if not synconly:
            for version in self.get_versions(vault):
                if not version.get('deleted'):
                    self.update_version(vault, version)
        return item

    # Synchronization

    def get_vector(self, vault):
        """Return a vector containing the latest versions for each node that
        we know of."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'No such vault')
        vector = self.database.execute('items', """
                    SELECT $origin$node,MAX($origin$seqnr)
                    FROM items
                    WHERE $vault = ?
                    GROUP BY $origin$node""", (vault,))
        return vector

    def get_items(self, vault, vector=None):
        """Return the items in `vault` that are newer than `vector`."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if vector is not None:
            if not isinstance(vector, (tuple, list)):
                raise ModelError('InvalidArgument', 'Illegal vector')
            for elem in vector:
                if not isinstance(elem, (tuple, list)) or len(elem) != 2 or \
                        not uuid4.check(elem[0]) or \
                        not isinstance(elem[1], compat.integer_types):
                    raise ModelError('InvalidArgument', 'Illegal vector')
        if vault not in self.vaults:
            raise ModelError('NotFound', 'no such vault')
        query = '$vault = ?'
        args = [vault]
        if vector is not None:
            nodes = self.database.execute('items',
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
        return self.database.findall('items', query, args)

    def import_item(self, vault, item, notify=True):
        """Import a single item."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault UUID')
        status, detail = self.check_item(item)
        if not status:
            raise ModelError('InvalidArgument', 'Invalid item: %s' % detail)
        if item['payload']['_type'] == 'Certificate':
            status, detail = self.check_certificate(item)
            if not status:
                raise ModelError('InvalidArgument', 'Invalid cert: %s' % detail)
            self.database.insert('items', item)
            self._log.debug('imported certificate, re-calculating trust')
            self._calculate_trust(item['vault'])
            # Find items that are signed by this certificate
            query = "$vault = ? AND $payload$_type = 'EncryptedItem'" \
                    " AND $origin$node = ?"
            args = (vault, item['payload']['node'])
            items = self.database.findall('items', query, args)
        elif item['payload']['_type'] == 'EncryptedItem':
            status, detail = self.check_encrypted_item(item)
            if not status:
                raise ModelError('InvalidArgument',
                                 'Invalid encrypted item: %s' % detail)
            self.database.insert('items', item)
            items = [item]
        else:
            raise ModelError('InvalidArgument', 'Unknown payload type')
        if self.vault_is_locked(vault):
            return
        # See if the wider set of certificates exposed some versions
        versions = []
        for item in items:
            if not self._verify_item(vault, item) or \
                    not self._decrypt_item(vault, item) or \
                    not self.check_decrypted_item(item)[0] or \
                    not self.check_version(item)[0]:
                continue
            versions.append(item)
        self._log.debug('updating version cache for {} versions', len(versions))
        self._update_version_cache(versions, notify=notify)

    def import_items(self, vault, items, notify=True):
        """Import multiple items. This is more efficient than calling
        import_item() multiple times. Items with errors are silently skipped
        and do not prevent good items to be imported."""
        if not uuid4.check(vault):
            raise ModelError('InvalidArgument', 'Illegal vault uuid')
        if vault not in self.vaults:
            raise ModelError('NotFound')
        self._log.debug('importing {} items', len(items))
        items = [ item for item in items if self.check_item(item)[0] ]
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
                  if item['payload']['_type'] == 'Certificate'
                        and self.check_certificate(item)[0] ]
        if certs:
            # It is safe to import any certificate. Certificates require
            # a trusted signature before they are considered trusted.
            self.database.insert_many('items', certs)
            self._calculate_trust(vault)
            self._log.debug('imported {} certificates and recalculated trust', len(certs))
            # Some items may have become exposed by the certs. Find items
            # that were signed by the certs we just added.
            query = "$vault = ? AND $payload$_type = 'EncryptedItem'"
            query += ' AND (%s)' % ' OR '.join([ '$origin$node = ?' ] * len(certs))
            args = [ vault ]
            args += [ cert['payload']['node'] for cert in certs ]
            certitems = self.database.findall('items', query, args)
            self._log.debug('{} items are possibly touched by these certs', len(certitems))
        else:
            certitems = []
        # Now see which items are valid under the possibly wider set of
        # certificates and add them
        encitems = [ item for item in items
                     if item['payload']['_type'] == 'EncryptedItem'
                            and self.check_encrypted_item(item)[0] ]
        self.database.insert_many('items', encitems)
        self._log.debug('imported {} encrypted items', len(encitems))
        # Update version and history caches (if the vault is unlocked)
        if not self.vault_is_locked(vault):
            versions = []
            for item in itertools.chain(encitems, certitems):
                if not self._verify_item(vault, item) or \
                        not self._decrypt_item(vault, item) or \
                        not self.check_decrypted_item(item)[0] or \
                        not self.check_version(item)[0]:
                    continue
                versions.append(item)
            self._update_version_cache(versions, notify=notify)
        return len(certs) + len(encitems)
