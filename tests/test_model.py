#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import time
import socket
import logging
import six

from tests.support import *
from bluepass.store import *
from bluepass.model import *
from bluepass.model import copy_dict
from bluepass import base64, crypto


class TestModel(UnitTest):
    """Unit tests for Model."""

    def setUp(self):
        super(TestModel, self).setUp()
        self.filename = self.tempname()
        self.store = Store(self.filename)
        self.model = Model(self.store)

    def tearDown(self):
        super(TestModel, self).tearDown()
        self.store.close()

    def test_config_crud(self):
        # Ensure that basic CRUD operations on a config work.
        model = self.model
        config = model.create_config({'name': 'foo'})
        self.assertIsInstance(config, dict)
        self.assertIn('name', config)
        config2 = model.get_config('foo')
        self.assertIsInstance(config, dict)
        self.assertEqual(config2, config)
        configs = model.get_configs()
        self.assertIsInstance(configs, list)
        self.assertEqual(configs, [config])
        config['foo'] = 'bar'
        config2 = model.update_config('foo', config)
        self.assertIsInstance(config2, dict)
        config2 = model.get_config('foo')
        self.assertEqual(config, config2)
        config2 = model.get_config('bar')
        self.assertIsNone(config2)
        configs = model.get_configs()
        self.assertIsInstance(configs, list)
        self.assertEqual(configs, [config])
        model.delete_config('foo')
        config2 = model.get_config('foo')
        self.assertIsNone(config2)
        configs = model.get_configs()
        self.assertEqual(configs, [])

    def test_config_persist(self):
        # Ensure that configurations persist on disk.
        model = self.model
        model.create_config({'name': 'foo'})
        config = model.get_config('foo')
        self.assertIsInstance(config, dict)
        self.assertEqual(config['name'], 'foo')
        self.store.close()
        store2 = Store(self.filename)
        model2 = Model(store2)
        config = model2.get_config('foo')
        self.assertIsInstance(config, dict)
        self.assertEqual(config['name'], 'foo')
        store2.close()

    def test_config_unique_name(self):
        # Ensure that no two configs with the same name can be created.
        model = self.model
        model.create_config({'name': 'foo'})
        self.assertRaises(StoreError, model.create_config, {'name': 'foo'})

    def test_token_crud(self):
        # Ensure that basic CRUD operations on a token work.
        model = self.model
        token = model.create_token({'expires': 0, 'allow': {'control_api': True}})
        self.assertIsInstance(token, dict)
        self.assertIn('id', token)
        token2 = model.get_token(token['id'])
        self.assertEqual(token, token2)
        tokens = model.get_tokens()
        self.assertIsInstance(tokens, list)
        self.assertEqual(tokens, [token])
        token['allow']['control_api'] = None  # delete
        token['allow']['client_api'] = False
        token2 = model.update_token(token['id'], token)
        self.assertIsInstance(token2, dict)
        del token['allow']['control_api']
        self.assertEqual(token2, token)
        token2 = model.get_token(token['id'])
        self.assertEqual(token2, token)
        token2 = model.get_token('foo')
        self.assertIsNone(token2)
        tokens = model.get_tokens()
        self.assertEqual(tokens, [token])
        model.delete_token(token['id'])
        token2 = model.get_token(token['id'])
        self.assertIsNone(token2)
        tokens = model.get_tokens()
        self.assertEqual(tokens, [])

    def test_token_persist(self):
        # Ensure that persistent tokens persist.
        model = self.model
        expires = time.time() + 10
        token = model.create_token({'expires': expires, 'allow': {}})
        self.store.close()
        store2 = Store(self.filename)
        model2 = Model(store2)
        token2 = model2.get_token(token['id'])
        self.assertEqual(token2, token)
        store2.close()

    def test_token_ephemeral(self):
        # Ensure that ephemeral tokens don't persist.
        model = self.model
        token = model.create_token({'expires': 0, 'allow': {}})
        model2 = Model(self.store)
        token2 = model2.get_token(token['id'])
        self.assertIsNone(token2)

    def test_token_validate(self):
        # Ensure that token validation works.
        model = self.model
        token = model.create_token({'expires': 0, 'allow': {'control_api': True}})
        self.assertTrue(model.validate_token(token['id']))
        self.assertTrue(model.validate_token(token['id'], 'control_api'))
        self.assertFalse(model.validate_token(token['id'], 'client_api'))
        expires = time.time() + 10
        token = model.create_token({'expires': expires, 'allow': {'control_api': True}})
        self.assertTrue(model.validate_token(token['id']))
        self.assertTrue(model.validate_token(token['id'], 'control_api'))
        self.assertFalse(model.validate_token(token['id'], 'client_api'))
        expires = time.time() - 10
        token = model.create_token({'expires': expires, 'allow': {'control_api': True}})
        self.assertFalse(model.validate_token(token['id']))

    def test_vault_crud(self):
        #Ensure that basic CRUD operations on a vault work.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        self.assertEqual(vault['name'], 'My Vault')
        self.assertIn('id', vault)
        self.assertIn('node', vault)
        uuid = vault['id']
        vault2 = model.get_vault(uuid)
        self.assertIsInstance(vault2, dict)
        self.assertEqual(vault2, vault)
        vaults = model.get_vaults()
        self.assertIsInstance(vaults, list)
        self.assertEqual(vaults, [vault])
        vault2 = model.update_vault(uuid, {'name': 'Updated'})
        self.assertEqual(vault2['name'], 'Updated')
        vault['name'] = 'Updated'
        self.assertEqual(vault2, vault)
        vault2 = model.get_vault(uuid)
        self.assertEqual(vault2, vault)
        vaults = model.get_vaults()
        self.assertEqual(vaults, [vault])
        vault2 = model.get_vault('foo')
        self.assertIsNone(vault2)
        model.delete_vault(uuid)
        vault2 = model.get_vault(uuid)
        self.assertIsNone(vault2)
        vaults = model.get_vaults()
        self.assertEqual(vaults, [])

    def test_vault_persist(self):
        # Ensure that a vault persists on disk.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        uuid = vault['id']
        vault2 = model.get_vault(uuid)
        self.assertEqual(vault2, vault)
        self.store.close()
        store2 = Store(self.filename)
        model2 = Model(store2)
        vault2 = model2.get_vault(uuid)
        self.assertEqual(vault2, vault)
        store2.close()

    def test_vault_signals(self):
        # Ensure that appropriate signals are raised when changing vaults.
        signals = []
        def callback(*args):
            if args[0].startswith('Vault'):
                signals.append(args)
        model = self.model
        model.add_callback(callback)
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        uuid = vault['id']
        vault2 = model.update_vault(uuid, {'name': 'My Vault2'})
        model.lock_vault(uuid)
        model.unlock_vault(uuid, 'Passw0rd')
        model.delete_vault(uuid)
        self.assertEqual(signals[0], ('VaultCreated', vault))
        self.assertEqual(signals[1], ('VaultUpdated', vault2))
        self.assertEqual(signals[2], ('VaultLocked', uuid))
        self.assertEqual(signals[3], ('VaultUnlocked', uuid))
        self.assertEqual(signals[4], ('VaultDeleted', uuid))

    def test_vault_lock_unlock(self):
        # Ensure that a vault can be locked and unlocked.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        uuid = vault['id']
        self.assertEqual(model.get_vault_status(uuid), 'UNLOCKED')
        model.lock_vault(uuid)
        self.assertEqual(model.get_vault_status(uuid), 'LOCKED')
        model.unlock_vault(uuid, 'Passw0rd')
        self.assertEqual(model.get_vault_status(uuid), 'UNLOCKED')
        model.unlock_vault(uuid, '', ('foo', 'bar'))
        self.assertEqual(model.get_vault_status(uuid), 'UNLOCKED')

    def test_vault_unlock_wrong_password(self):
        # Ensure that unlock with a wrong password raises InvalidPassword.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        uuid = vault['id']
        model.lock_vault(uuid)
        self.assertEqual(model.get_vault_status(uuid), 'LOCKED')
        self.assertRaises(InvalidPassword, model.unlock_vault, uuid, 'foo')
        self.assertEqual(model.get_vault_status(uuid), 'LOCKED')

    def test_vault_change_password(self):
        # Ensure that changing a password on a vault works.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        uuid = vault['id']
        model.update_vault(uuid, {'password': 'Passw1rd'})
        model.lock_vault(uuid)
        self.assertEqual(model.get_vault_status(uuid), 'LOCKED')
        self.assertRaises(InvalidPassword, model.unlock_vault, uuid, 'Passw0rd')
        self.assertEqual(model.get_vault_status(uuid), 'LOCKED')
        model.unlock_vault(uuid, 'Passw1rd')
        self.assertEqual(model.get_vault_status(uuid), 'UNLOCKED')

    def test_vault_statistics(self):
        # Ensure that statistics can be retrieved for a vault.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        uuid = vault['id']
        stats = model.get_vault_statistics(uuid)
        self.assertIsInstance(stats, dict)
        self.assertEqual(stats['current_secrets'], 0)
        self.assertEqual(stats['total_secrets'], 0)
        self.assertEqual(stats['linear_history_size'], 0)
        self.assertEqual(stats['full_history_size'], 0)
        self.assertEqual(stats['total_items'], 1)
        self.assertEqual(stats['total_certificates'], 1)
        self.assertEqual(stats['total_nodes'], 1)
        self.assertEqual(stats['trusted_nodes'], 1)

    def test_secret_crud(self):
        # Ensure that basic CRUD operations on a secret work.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        vltid = vault['id']
        model.unlock_vault(vault['id'], '', cache_fields=('foo',))
        secret = model.create_secret(vault['id'], {'fields': {'foo': 'bar'}})
        self.assertIsInstance(secret, dict)
        self.assertIsInstance(secret['id'], six.string_types)
        self.assertIsInstance(secret['version'], six.string_types)
        self.assertEqual(secret['type'], 'Secret')
        self.assertIsInstance(secret['created_at'], float)
        self.assertEqual(secret['fields'], {'foo': 'bar'})
        self.assertFalse(secret.get('deleted'))
        secid = secret['id']
        secret2 = model.get_secret(vltid, secid)
        self.assertEqual(secret2, secret)
        secrets = model.get_secrets(vltid)
        self.assertEqual(secrets, [secret])
        update = {'fields': {'foo': None, 'baz': 'qux'}}
        secret2 = model.update_secret(vltid, secid, update)
        self.assertIsInstance(secret2, dict)
        self.assertEqual(secret2['id'], secret['id'])
        self.assertNotEqual(secret2['version'], secret['version'])
        self.assertEqual(secret2['parent'], secret['version'])
        self.assertEqual(secret2['type'], 'Secret')
        self.assertEqual(secret2['fields'], {'baz': 'qux'})
        self.assertGreater(secret2['created_at'], secret['created_at'])
        self.assertFalse(secret2.get('deleted'))
        secret3 = model.delete_secret(vltid, secid)
        self.assertIsInstance(secret3, dict)
        self.assertEqual(secret3['id'], secret['id'])
        self.assertNotEqual(secret3['version'], secret2['version'])
        self.assertEqual(secret3['parent'], secret2['version'])
        self.assertEqual(secret3['type'], 'Secret')
        self.assertEqual(secret3['fields'], {})
        self.assertGreater(secret3['created_at'], secret2['created_at'])
        self.assertTrue(secret3['deleted'])
        secret4 = model.get_secret(vltid, secid)
        self.assertIsNone(secret4)
        secret4 = model.get_secret(vltid, 'foo')
        self.assertIsNone(secret4)

    def test_secret_get_paged(self):
        # Ensure that secrets can be retrieved incrementally.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        model.unlock_vault(vault['id'], '', cache_fields=('count',))
        ref = []
        for i in range(100):
            secret = model.create_secret(vault['id'], {'fields': {'count': i}})
            ref.append(secret)
        secrets = []
        last = None
        while len(secrets) < len(ref):
            batch = model.get_secrets(vault['id'], maxitems=10, after=last)
            secrets.extend(batch)
            last = batch[-1]['id']
        self.assertEqual(len(secrets), len(ref))
        self.assertEqual(secrets, sorted(ref, key=lambda s: s['id']))

    def test_secret_get_history(self):
        # Ensure that a secret's history can be retrieved.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        model.unlock_vault(vault['id'], '', cache_fields=('count',))
        secret = model.create_secret(vault['id'], {'fields': {'count': 0}})
        ref = [secret]
        for i in range(1, 10):
            secret = model.update_secret(vault['id'], secret['id'], {'fields': {'count': i}})
            ref.append(secret)
        history = model.get_secret_history(vault['id'], secret['id'])
        self.assertEqual(len(history), len(ref))
        self.assertEqual(history, list(reversed(ref)))

    def test_secret_signals(self):
        # Ensure that the right signals are raised when modifying secrets.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        model.unlock_vault(vault['id'], '', cache_fields=('count',))
        signals = []
        def callback(*args):
            if args[0].startswith('Secret'):
                signals.append(args)
        model.add_callback(callback)
        ref = []
        for i in range(10):
            secret = model.create_secret(vault['id'], {'fields': {'count': i}})
            ref.append(secret)
        for i in range(10):
            self.assertEqual(signals[i], ('SecretsAdded', vault['id'], [ref[i]]))

    # Synchronization

    def test_sync_get_auth_key(self):
        # Ensure auth key is available even when vault is locked.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        key = model.get_auth_key(vault['id'])
        self.assertIsNotNone(key)
        self.assertIsInstance(key, bytes)
        self.assertGreater(len(key), 15)
        model.lock_vault(vault['id'])
        key2 = model.get_auth_key(vault['id'])
        self.assertEqual(key2, key)

    def test_sync_get_vector(self):
        # Test the get_vector() method.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        seqnr = -1
        for i in range(10):
            secret = model.create_secret(vault['id'], {'fields': {}})
            vector = model.get_vector(vault['id'])
            self.assertIsInstance(vector, list)
            self.assertEqual(len(vector), 1)
            self.assertIsInstance(vector[0], tuple)
            self.assertEqual(len(vector[0]), 2)
            self.assertEqual(vector[0][0], vault['node'])
            self.assertGreater(vector[0][1], seqnr)
            seqnr = vector[0][1]

    def test_sync_cr_certificate(self):
        # Test adding and retrieving a certificate.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        cert = model.get_certificate(vault['id'], vault['node'])
        self.assertIsInstance(cert, dict)
        self.assertEqual(cert['node'], vault['node'])
        keys = cert.get('keys')
        self.assertIsInstance(keys, dict)
        for keyname in ('auth', 'encrypt', 'sign'):
            self.assertIn(keyname, keys)
            self.assertIsInstance(keys[keyname], dict)
            self.assertEqual(len(keys[keyname]), 2)
            self.assertIsInstance(keys[keyname]['keytype'], six.string_types)
            self.assertIsInstance(keys[keyname]['public'], six.string_types)
        template = {'node': crypto.random_uuid(), 'name': 'foo', }
        keys = template['keys'] = {}
        random = base64.encode(crypto.random_bytes(64))
        keys['sign'] = {'keytype': 'ed25519', 'public': random}
        keys['encrypt'] = {'keytype': 'curve25519', 'public': random}
        keys['auth'] = {'keytype': 'ed25519', 'public': random}
        cert = model.create_certificate(vault['id'], template)
        self.assertIsInstance(cert, dict)
        self.assertIn('id', cert)
        self.assertIsInstance(cert['id'], six.string_types)
        self.assertEqual(cert['node'], template['node'])
        self.assertEqual(cert['name'], template['name'])
        self.assertEqual(cert['keys'], template['keys'])
        cert2 = model.get_certificate(vault['id'], cert['node'])
        self.assertEqual(cert2, cert)

    def test_sync_get_items(self):
        # Test the get_items() method.
        model = self.model
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        items = model.get_items(vault['id'])
        # There should be 1 item which is the self-signed cert for the vault
        self.assertIsInstance(items, list)
        self.assertEqual(len(items), 1)
        self.assertIsInstance(items[0], dict)
        payload = items[0].get('payload')
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload['type'], 'Certificate')
        self.assertEqual(payload['node'], vault['node'])
        self.assertIsInstance(payload['name'], six.string_types)
        self.assertIsInstance(payload['keys'], dict)
        self.assertEqual(len(payload['keys']), 3)
        for keyname in ('auth', 'encrypt', 'sign'):
            self.assertIn(keyname, payload['keys'])
            self.assertIsInstance(payload['keys'][keyname], dict)
        vector = model.get_vector(vault['id'])
        # For each secret that we add, one more item will be added
        for i in range(10):
            secret = model.create_secret(vault['id'], {'fields': {}})
            items = model.get_items(vault['id'], vector)
            self.assertIsInstance(items, list)
            self.assertEqual(len(items), 1)
            self.assertIsInstance(items[0], dict)
            payload = items[0].get('payload')
            self.assertIsInstance(payload, dict)
            self.assertEqual(payload['type'], 'Encrypted')
            self.assertIsInstance(payload['blob'], six.string_types)
            self.assertIsInstance(payload['keys'], dict)
            self.assertEqual(len(payload['keys']), 1)
            self.assertIn(vault['node'], payload['keys'])
            self.assertIsInstance(payload['keys'][vault['node']], six.string_types)
            vector = model.get_vector(vault['id'])

    def test_sync_signals(self):
        # Ensure that the proper signals are raised when adding items.
        model = self.model
        signals = []
        def callback(*args):
            if args[0].startswith('Item'):
                signals.append(args)
        model.add_callback(callback)
        vault = model.create_vault({'name': 'My Vault', 'password': 'Passw0rd'})
        vectors = [self.model.get_vector(vault['id'])]
        for i in range(10):
            vectors.append(self.model.get_vector(vault['id']))
            model.create_secret(vault['id'], {'fields': {}})
        self.assertEqual(len(signals), len(vectors))
        for i in range(len(signals)):
            self.assertEqual(signals[i], ('ItemsAdded', vault['id'], vectors[i]))

    def test_sync_secrets(self):
        # Test synchronizing secrets between two vaults.
        # First create two vaults that are synchronized to each other.
        model1 = self.model
        model1._log.context = 'Model#1'
        vault1 = model1.create_vault({'name': 'V1', 'password': 'P1'})
        secret1 = model1.create_secret(vault1['id'], {'fields': {'foo': 'bar'}})
        store2 = Store(self.tempname('store2'))
        model2 = Model(store2)
        model2._log.context = 'Model#2'
        vault2 = model2.create_vault({'id': vault1['id'], 'name': 'V2', 'password': 'P2'})
        self.assertEqual(vault2['id'], vault1['id'])
        vault = vault1
        template2 = {'name': 'Node2', 'node': vault2['node'],
                     'keys': model2.get_public_keys(vault['id'])}
        cert1 = model1.create_certificate(vault1['id'], template2)
        template1 = {'name': 'Node1', 'node': vault1['node'],
                     'keys': model1.get_public_keys(vault1['id'])}
        cert2 = model2.create_certificate(vault2['id'], template1)
        model1.import_items(vault1['id'], model2.get_items(vault1['id']))
        model2.import_items(vault['id'], model1.get_items(vault['id']))
        secret2 = model2.get_secret(vault['id'], secret1['id'])
        self.assertEqual(secret2, secret1)
        self.assertEqual(secret2['fields']['foo'], 'bar')
        secret = secret1
        # Update the secret in vault1 and sync it to vault2. The update should
        # become available in vault1.
        secret1u = model1.update_secret(vault['id'], secret['id'], {'fields': {'foo': 'baz'}})
        model2.import_items(vault['id'], model1.get_items(vault['id']))
        secret2u = model2.get_secret(vault['id'], secret['id'])
        self.assertEqual(secret2u, secret1u)
        self.assertEqual(secret2u['fields']['foo'], 'baz')
        # Update in vault2 and sync to vault1.
        secret2u = model2.update_secret(vault['id'], secret['id'], {'fields': {'foo': 'qux'}})
        model1.import_items(vault['id'], model2.get_items(vault['id']))
        secret1u = model1.get_secret(vault['id'], secret['id'])
        self.assertEqual(secret1u, secret2u)
        self.assertEqual(secret1u['fields']['foo'], 'qux')
        store2.close()

    def test_sync_concurrent_update(self):
        # Test the conflict resolution algorithm that takes place for
        # concurrent updates.
        # First create two vaults that are synchronized to each other.
        model1 = self.model
        model1._log.context = 'Model#1'
        vault1 = model1.create_vault({'name': 'V1', 'password': 'P1'})
        secret1 = model1.create_secret(vault1['id'], {'fields': {'foo': 'bar'}})
        store2 = Store(self.tempname('store2'))
        model2 = Model(store2)
        model2._log.context = 'Model#2'
        vault2 = model2.create_vault({'id': vault1['id'], 'name': 'V2', 'password': 'P2'})
        self.assertEqual(vault2['id'], vault1['id'])
        vault = vault1
        template2 = {'name': 'Node2', 'node': vault2['node'],
                     'keys': model2.get_public_keys(vault['id'])}
        cert1 = model1.create_certificate(vault1['id'], template2)
        template1 = {'name': 'Node1', 'node': vault1['node'],
                     'keys': model1.get_public_keys(vault1['id'])}
        cert2 = model2.create_certificate(vault2['id'], template1)
        model1.import_items(vault1['id'], model2.get_items(vault1['id']))
        model2.import_items(vault['id'], model1.get_items(vault['id']))
        secret2 = model2.get_secret(vault['id'], secret1['id'])
        self.assertEqual(secret2, secret1)
        secret = secret1
        # Update the secret both in vault1 and vault2. The most recent one wins.
        secret1u = model1.update_secret(vault['id'], secret['id'], {'fields': {'foo': 'model1'}})
        self.assertEqual(secret1u['id'], secret['id'])
        time.sleep(0.01)
        secret2u = model2.update_secret(vault['id'], secret['id'], {'fields': {'foo': 'model2'}})
        self.assertEqual(secret2u['id'], secret['id'])
        model2.import_items(vault['id'], model1.get_items(vault['id']))
        secret2u = model2.get_secret(vault['id'], secret['id'])
        self.assertEqual(secret2u['fields']['foo'], 'model2')
        # Now resurrect the lineage of secret1 by adding a newer child to it
        time.sleep(0.01)
        secret1u = model1.update_secret(vault['id'], secret['id'], {'fields': {}})
        model2.import_items(vault['id'], model1.get_items(vault['id']))
        secret2u = model2.get_secret(vault['id'], secret['id'])
        self.assertEqual(secret2u, secret1u)
        self.assertEqual(secret2u['fields']['foo'], 'model1')
        # Sync to vault 1 and esure the same secret is active there too
        model1.import_items(vault['id'], model2.get_items(vault['id']))
        secret1u = model1.get_secret(vault['id'], secret['id'])
        self.assertEqual(secret1u, secret2u)
        store2.close()

    def test_sync_cert_keys(self):
        # Ensure that certificates with a subset of keys can be created, and
        # that those only give access to the right subset of functionality.
        model1 = self.model
        model1._log.context = 'Model#1'
        vault1 = model1.create_vault({'name': 'V1', 'password': 'P1'})
        secret1 = model1.create_secret(vault1['id'], {'fields': {'foo': 'bar'}})
        store2 = Store(self.tempname('store2'))
        model2 = Model(store2)
        model2._log.context = 'Model#2'
        vault2 = model2.create_vault({'id': vault1['id'], 'name': 'V2', 'password': 'P2'})
        self.assertEqual(vault2['id'], vault1['id'])
        vault = vault1
        # Node2 trusts node1 fully, but node1 only signs an "auth" key for node2.
        template1 = {'name': 'Node1', 'node': vault1['node'],
                     'keys': model1.get_public_keys(vault1['id'])}
        cert2 = model2.create_certificate(vault['id'], template1)
        keys = copy_dict(model2.get_public_keys(vault['id']), include=('auth',))
        template2 = {'name': 'Node2', 'node': vault2['node'], 'keys': keys}
        cert1 = model1.create_certificate(vault['id'], template2)
        model1.import_items(vault['id'], model2.get_items(vault['id']))
        model2.import_items(vault['id'], model1.get_items(vault['id']))
        # Node2 should not be able to read secret1
        secret2 = model2.get_secret(vault['id'], secret1['id'])
        self.assertIsNone(secret2)
        # Now add a new cert with a "decrypt" key. Node2 should be able to read the secret.
        keys = copy_dict(model2.get_public_keys(vault['id']), include=('encrypt',))
        template2 = {'name': 'Node2', 'node': vault2['node'], 'keys': keys}
        cert1 = model1.create_certificate(vault['id'], template2)
        model2.import_items(vault['id'], model1.get_items(vault['id']))
        secret2 = model2.get_secret(vault['id'], secret1['id'])
        self.assertEqual(secret2, secret1)
        secret = secret1
        # An update signed by node2 still does not get through...
        secret2u = model2.update_secret(vault['id'], secret['id'], {'fields': {'foo': 'baz'}})
        model1.import_items(vault['id'], model2.get_items(vault['id']))
        secret1u = model1.get_secret(vault['id'], secret['id'])
        self.assertEqual(secret1u, secret)
        self.assertEqual(secret1u['fields']['foo'], 'bar')
        # Now finally add an "auth" key. The updated secret should become available.
        keys = copy_dict(model2.get_public_keys(vault['id']), include=('sign',))
        template2 = {'name': 'Node2', 'node': vault2['node'], 'keys': keys}
        cert1 = model1.create_certificate(vault['id'], template2)
        secret1u = model1.get_secret(vault['id'], secret['id'])
        self.assertEqual(secret1u, secret2u)
        self.assertEqual(secret1u['fields']['foo'], 'baz')
        store2.close()

    def test_sync_transitive_trust(self):
        # Ensure that trust conveyed by a certificate is transitive.
        model1 = self.model
        model1._log.context = 'Model#1'
        vault1 = model1.create_vault({'name': 'V1', 'password': 'P1'})
        secret1 = model1.create_secret(vault1['id'], {'fields': {'foo': 'bar'}})
        store2 = Store(self.tempname('store2'))
        model2 = Model(store2)
        model2._log.context = 'Model#2'
        vault2 = model2.create_vault({'id': vault1['id'], 'name': 'V2', 'password': 'P2'})
        self.assertEqual(vault2['id'], vault1['id'])
        model2.import_items(vault1['id'], model1.get_items(vault1['id']))
        store3 = Store(self.tempname('store3'))
        model3 = Model(store3)
        model3._log.context = 'Model#3'
        vault3 = model3.create_vault({'id': vault1['id'], 'name': 'V3', 'password': 'P3'})
        self.assertEqual(vault3['id'], vault1['id'])
        model3.import_items(vault1['id'], model1.get_items(vault1['id']))
        vault = vault1
        # Node3 trusts node1.
        template1 = {'name': 'Node1', 'node': vault1['node'],
                     'keys': model1.get_public_keys(vault1['id'])}
        cert3 = model3.create_certificate(vault['id'], template1)
        # Node2 trusts node3
        template3 = {'name': 'Node3', 'node': vault3['node'],
                     'keys': model3.get_public_keys(vault3['id'])}
        cert2 = model2.create_certificate(vault['id'], template3)
        # There is no transitive trust path from node1 to node3, so node3
        # should not be able to see secret1
        model1.import_items(vault['id'], model2.get_items(vault['id']))
        model3.import_items(vault['id'], model1.get_items(vault['id']))
        secret3 = model3.get_secret(vault['id'], secret1['id'])
        self.assertIsNone(secret3)
        # Now make node1 trust node2. This adds a transitive trust to node3.
        template2 = {'name': 'Node2', 'node': vault2['node'],
                     'keys': model2.get_public_keys(vault1['id'])}
        cert1 = model1.create_certificate(vault['id'], template2)
        # The above should have re-addressed secret1 to node2 *and* node3.
        model3.import_items(vault['id'], model1.get_items(vault['id']))
        secret3 = model3.get_secret(vault['id'], secret1['id'])
        self.assertEqual(secret3, secret1)
        # The secret is also addressed to node2, but node2 doesn't trust node1 yet.
        model2.import_items(vault['id'], model1.get_items(vault['id']))
        secret2 = model2.get_secret(vault['id'], secret1['id'])
        self.assertIsNone(secret2)
        # Make node2 trust node1. The secret should be available to node2
        cert2 = model2.create_certificate(vault['id'], template1)
        secret2 = model2.get_secret(vault['id'], secret1['id'])
        self.assertEqual(secret2, secret1)
        store2.close()
        store3.close()


if __name__ == '__main__':
    unittest.main()
