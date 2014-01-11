#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import time
import socket
import logging

from unit import *
from bluepass.database import *
from bluepass.model import *


class TestModel(UnitTest):

    def setUp(self):
        self.filename = self.tempfile()
        self.database = Database(self.filename)
        self.model = Model(self.database)

    def tearDown(self):
        self.database.close()

    def test_config(self):
        model = self.model
        config = model.get_config()
        assert isinstance(config, dict)
        assert 'id' in config
        config['foo'] = 'bar'
        config['baz'] = { 'qux': 'quux' }
        model.update_config(config)
        config2 = model.get_config()
        assert config == config2

    def test_create_vault(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        assert vault['name'] == 'My Vault'
        assert 'id' in vault
        assert 'node' in vault
        assert 'keys' in vault

    def test_get_vaults(self):
        model = self.model
        uuid = model.create_vault('My Vault', 'Passw0rd')
        uuid2 = model.create_vault('His Vault', 'Passw0rd')
        vaults = model.get_vaults()
        assert len(vaults) == 2
        assert vaults[0]['name'] in ('My Vault', 'His Vault')
        assert vaults[1]['name'] in ('My Vault', 'His Vault')
        assert vaults[0]['name'] != vaults[1]['name']

    def test_update_vault(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        assert vault['name'] == 'My Vault'
        vault['name'] = 'His Vault'
        model.update_vault(vault)
        vault2 = model.get_vault(vault['id'])
        assert vault2['name'] == 'His Vault'

    def test_delete_vault(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        assert vault['name'] == 'My Vault'
        model.delete_vault(vault)
        vault = model.get_vault(vault['id'])
        assert vault is None

    def test_lock_vault(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        assert not model.vault_is_locked(vault['id'])
        model.lock_vault(vault['id'])
        assert model.vault_is_locked(vault['id'])

    def test_unlock_vault(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        assert not model.vault_is_locked(vault['id'])
        model.lock_vault(vault['id'])
        assert model.vault_is_locked(vault['id'])
        model.unlock_vault(vault['id'], 'Passw0rd')
        assert not model.vault_is_locked(vault['id'])

    def test_vault_open_close(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        version = model.add_version(vault['id'], {'foo': 'bar'})
        assert version['foo'] == 'bar'
        self.database.close()
        model2 = Model(Database(self.filename))
        model2.unlock_vault(vault['id'], 'Passw0rd')
        version2 = model2.get_version(vault['id'], version['id'])
        assert version2 is not None
        assert version2['foo'] == 'bar'

    def test_vault_password(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        version = model.add_version(vault['id'], {'foo': 'bar'})
        assert version['foo'] == 'bar'
        model.lock_vault(vault['id'])
        err = self.assertRaises(ModelError, model.get_version, vault['id'], version['id'])
        assert err.error_name == 'Locked'
        err = self.assertRaises(ModelError, model.unlock_vault, vault['id'], 'Passw!rd')
        assert err.error_name == 'WrongPassword'
        assert model.vault_is_locked(vault['id'])
        err = self.assertRaises(ModelError, model.get_version, vault['id'], version['id'])
        assert err.error_name == 'Locked'
        model.unlock_vault(vault['id'], 'Passw0rd')
        assert not model.vault_is_locked(vault['id'])
        version = model.get_version(vault['id'], version['id'])
        assert version is not None
        assert version['foo'] == 'bar'

    def test_add_version(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        version = model.add_version(vault['id'], {'foo': 'bar'})
        assert isinstance(version, dict)
        assert 'id' in version
        assert version['foo'] == 'bar'

    def test_update_version(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        version = model.add_version(vault['id'], {'foo': 'bar'})
        assert isinstance(version, dict)
        assert version['foo'] == 'bar'
        version['foo'] = 'baz'
        model.update_version(vault['id'], version)
        version2 = model.get_version(vault['id'], version['id'])
        assert version2['foo'] == 'baz'

    def test_delete_version(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        version = model.add_version(vault['id'], {'foo': 'bar'})
        version['deleted'] = True
        model.delete_version(vault['id'], version)
        history = model.get_version_history(vault['id'], version['id'])
        assert len(history) == 2
        assert 'id' in history[0]
        assert history[0]['id'] == history[1]['id']
        assert history[0]['deleted']
        version2 = model.get_version(vault['id'], version['id'])
        assert version2 is None

    def test_get_version_history(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        version = model.add_version(vault['id'], {'foo': 'bar'})
        assert version['foo'] == 'bar'
        version['foo'] = 'baz'
        model.update_version(vault['id'], version)
        version = model.get_version(vault['id'], version['id'])
        assert version['foo'] == 'baz'
        history = model.get_version_history(vault['id'], version['id'])
        assert len(history) == 2
        assert history[0]['foo'] == 'baz'
        assert history[1]['foo'] == 'bar'

    def test_concurrent_updates(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        version = model.add_version(vault['id'], {'foo': 'bar'})
        # Need to access some internals here to fake a concurrent update.
        vid = model._version_cache[vault['id']][version['id']]['payload']['id']
        def update_vid(vid, **kwargs):
            item = model._new_version(vault['id'], parent=vid, **kwargs)
            model._encrypt_item(vault['id'], item)
            model._add_origin(vault['id'], item)
            model._sign_item(vault['id'], item)
            model.import_item(vault['id'], item)
        update_vid(vid, id=version['id'], foo='baz')
        time.sleep(1)  # created_at has a resolution of 1 sec
        update_vid(vid, id=version['id'], foo='qux')
        history = model.get_version_history(vault['id'], version['id'])
        assert len(history) == 2
        assert history[0]['foo'] == 'qux'
        assert history[1]['foo'] == 'bar'

    def test_callbacks(self):
        model = self.model
        vault = model.create_vault('My Vault', 'Passw0rd')
        events = []
        def callback(event, *args):
            events.append((event, args))
        model.add_callback(callback)
        version = model.add_version(vault['id'], {'foo': 'bar'})
        assert len(events) == 1
        assert events[0] == ('VersionsAdded', (vault['id'], [version]))
        del version['foo']
        version['deleted'] = True
        version = model.delete_version(vault['id'], version)
        assert len(events) == 2
        assert events[1] == ('VersionsAdded', (vault['id'], [version]))

    def test_add_certificate(self):
        model1 = Model(Database(self.tempfile()))
        model2 = Model(Database(self.tempfile()))
        # Two vaults, with the same UUID, for pairng
        vault1 = model1.create_vault('My Vault', 'Passw0rd')
        vault2 = model2.create_vault('My Vault', 'Passw0rd', uuid=vault1['id'])
        assert vault1['id'] == vault2['id']
        version2 = model2.add_version(vault2['id'], {'foo': 'bar'})
        # Add certificate for node1 to node2. This will re-encrypt
        # the version for node1.
        certinfo = { 'node': vault1['node'], 'name': 'node1' }
        keys = certinfo['keys'] = {}
        for key in vault1['keys']:
            keys[key] = { 'key': vault1['keys'][key]['public'],
                          'keytype': vault1['keys'][key]['keytype'] }
        model2.add_certificate(vault2['id'], certinfo)
        history = model2.get_version_history(vault2['id'], version2['id'])
        assert len(history) == 2
        # Import items from model2 into model1. However, there is no cert
        # yet for node2, so the version should not become visible.
        items = model2.get_items(vault2['id'])
        model1.import_items(vault1['id'], items)
        version1 = model1.get_version(vault1['id'], version2['id'])
        assert version1 is None
        cert = model1.get_certificate(vault1['id'], vault2['node'])
        assert cert is None
        # Add a "synconly" certificate. This should not expose the version
        certinfo = { 'node': vault2['node'], 'name': 'node2' }
        keys = certinfo['keys'] = {}
        for key in vault1['keys']:
            keys[key] = { 'key': vault2['keys'][key]['public'],
                          'keytype': vault2['keys'][key]['keytype'] }
        certinfo['restrictions'] = { 'synconly': True }
        model1.add_certificate(vault1['id'], certinfo)
        cert = model1.get_certificate(vault1['id'], vault2['node'])
        assert cert is not None
        assert cert['payload']['node'] == vault2['node']
        assert cert['payload']['restrictions']['synconly']
        version1 = model1.get_version(vault1['id'], version2['id'])
        assert version1 is None
        # Now add a real certificate. the version should become visible now.
        certinfo = { 'node': vault2['node'], 'name': 'node2' }
        keys = certinfo['keys'] = {}
        for key in vault1['keys']:
            keys[key] = { 'key': vault2['keys'][key]['public'],
                          'keytype': vault2['keys'][key]['keytype'] }
        certinfo['restrictions'] = {}
        model1.add_certificate(vault1['id'], certinfo)
        cert = model1.get_certificate(vault1['id'], vault2['node'])
        assert cert is not None
        assert cert['payload']['node'] == vault2['node']
        assert not cert['payload'].get('restrictions', {}).get('synconly')
        version1 = model1.get_version(vault1['id'], version2['id'])
        assert version1 is not None
        assert version1['foo'] == 'bar'


if __name__ == '__main__':
    unittest.main()
