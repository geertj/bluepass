#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import json

from tests.support import *
from bluepass.store import *


class TestStore(UnitTest):
    """Unit test suite for Store."""

    def setUp(self):
        # Each test gets a fresh store.
        self.filename = self.tempname()
        self.store = Store(self.filename)
        self.store.create_collection('items')

    def tearDown(self):
        self.store.close()

    def test_insert(self):
        """Ensure that a basic insert() works."""
        store = self.store
        doc = { 'id': 1, 'foo': 'bar' }
        store.insert('items', doc)
        docs = store.findall('items')
        self.assertIn(doc, docs)
        self.assertEqual(len(docs), 1)
        store.close()
        store.open(self.filename)
        docs = store.findall('items')
        self.assertIn(doc, docs)
        self.assertEqual(len(docs), 1)

    @unix_only
    def test_open_locked(self):
        """Ensure that a different process cannot open a store that already
        open."""
        pid = os.fork()
        if pid == 0:
            try:
                store = Store(self.filename)
            except OSError:
                os._exit(0)
            os._exit(1)
        res = os.waitpid(pid, 0)
        self.assertEqual(os.WEXITSTATUS(res[1]), 0)

    def test_find_str(self):
        """Ensure that findall() can find a document using a match on an
        string key."""
        store = self.store
        store.insert('items', {'foo': 'bar'})
        store.insert('items', {'foo': 'baz'})
        docs = store.findall('items', '$foo=?', ('bar',))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['foo'], 'bar')

    def test_find_int(self):
        """Ensure that findall() can find a document using a match on an
        integer key."""
        store = self.store
        store.insert('items', {'foo': 1})
        store.insert('items', {'foo': 2})
        docs = store.findall('items', '$foo=?', (1,))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['foo'], 1)
        docs = store.findall('items', '$foo>?', (1,))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['foo'], 2)

    def test_find_boolean(self):
        """Ensure that findall() can find a document using an boolean match
        condition."""
        store = self.store
        store.insert('items', {'foo': 1, 'bar': 1})
        store.insert('items', {'foo': 2, 'bar': 1})
        docs = store.findall('items', '$foo=? OR $foo=?', (1,2))
        self.assertEqual(len(docs), 2)
        self.assertIn(docs[0]['foo'], (1, 2))
        self.assertIn(docs[1]['foo'], (1, 2))
        docs = store.findall('items', '$foo=? AND $bar=?', (1,1))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['foo'], 1)
        self.assertEqual(docs[0]['bar'], 1)

    def test_find_nested(self):
        """Ensure that findall() can find a document using a match on an
        nested attribute."""
        store = self.store
        store.insert('items', {'foo': {'bar': 1}})
        store.insert('items', {'foo': {'bar': 2}})
        docs = store.findall('items', '$foo$bar=?', (1,))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['foo']['bar'], 1)

    def test_find_with_index(self):
        """Ensure that findall() can find a document using a match on an
        index."""
        store = self.store
        store.create_index('items', '$foo', 'INTEGER')
        store.insert('items',{'foo': 1})
        store.insert('items',{'foo': 2})
        docs = store.findall('items','$foo==?', (1,))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['foo'], 1)
        store.close()
        store.open(self.filename)
        docs = store.findall('items','$foo==?', (1,))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['foo'], 1)

    def test_find_with_index_nested(self):
        """Ensure that findall() can find a document using a match on an
        index for a nested attribute."""
        store = self.store
        store.create_index('items', '$foo$bar', 'INTEGER')
        store.insert('items',{'foo': {'bar': 1}})
        store.insert('items',{'foo': {'bar': 2}})
        docs = store.findall('items','$foo$bar==?', (1,))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['foo']['bar'], 1)
        store.close()
        store.open(self.filename)
        docs = store.findall('items','$foo$bar==?', (1,))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]['foo']['bar'], 1)

    def test_findone(self):
        """Ensure that findone() finds a single document if at least one
        exists, or None if none exists."""
        store = self.store
        store.insert('items', {'foo': 1, 'bar': 1})
        store.insert('items', {'foo': 2, 'bar': 1})
        doc = store.findone('items', '$foo = 1')
        self.assertEqual(doc['foo'], 1)
        doc = store.findone('items', '$bar = 1')
        self.assertEqual(doc['bar'], 1)
        doc = store.findone('items', '$bar = 2')
        self.assertIsNone(doc)

    def test_insert_transaction(self):
        """Insert multiple documents in a single transaction. Ensure that all
        documents are added."""
        store = self.store
        with store.begin():
            store.insert('items', {'foo': 1})
            store.insert('items', {'foo': 2})
        docs = store.findall('items')
        self.assertEqual(len(docs), 2)
        store.close()
        store.open(self.filename)
        docs = store.findall('items')
        self.assertEqual(len(docs), 2)

    def test_insert_abort_transaction(self):
        """Insert and remove a document in a single transaction. Ensure that no
        document is addded."""
        store = self.store
        with store.begin() as cursor:
            store.insert('items', {'foo': 1})
            cursor.connection.rollback()
        docs = store.findall('items')
        self.assertEqual(len(docs), 0)
        store.close()
        store.open(self.filename)
        docs = store.findall('items')
        self.assertEqual(len(docs), 0)

    def test_update(self):
        """Ensure that update() really updates a document."""
        store = self.store
        store.insert('items', {'foo': 1, 'bar': 1})
        store.insert('items', {'foo': 2, 'bar': 2})
        docs = store.findall('items', '$bar=2')
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0], {'foo': 2, 'bar': 2 })
        doc = docs[0]
        doc['bar'] = 3
        store.update('items', doc, '$foo = ?', (2,))
        docs = store.findall('items')
        self.assertEqual(len(docs), 2)
        doc = store.findone('items', '$bar=3')
        self.assertEqual(doc, {'foo': 2, 'bar': 3})
        store.close()
        store.open(self.filename)
        docs = store.findall('items')
        self.assertEqual(len(docs), 2)
        doc = store.findone('items', '$bar=3')
        self.assertEqual(doc, {'foo': 2, 'bar': 3})

    def test_update_with_index(self):
        """Update a document with attributes that are indexed. Ensure that the
        indexes get updated."""
        store = self.store
        store.create_index('items', '$foo', 'INTEGER')
        store.create_index('items', '$bar', 'INTEGER')
        store.insert('items', {'foo': 1, 'bar': 1})
        store.insert('items', {'foo': 2, 'bar': 2})
        docs = store.findall('items', '$bar=2')
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0], {'foo': 2, 'bar': 2 })
        doc = docs[0]
        doc['bar'] = 3
        store.update('items', doc, '$foo=?', (2,))
        docs = store.findall('items')
        self.assertEqual(len(docs), 2)
        doc = store.findone('items', '$bar=3')
        self.assertEqual(doc, {'foo': 2, 'bar': 3})
        store.close()
        store.open(self.filename)
        docs = store.findall('items')
        self.assertEqual(len(docs), 2)
        doc = store.findone('items', '$bar=3')
        self.assertEqual(doc, {'foo': 2, 'bar': 3})

    def test_delete(self):
        """Ensure that delete() really deletes a document."""
        store = self.store
        store.insert('items', {'foo': 1, 'bar': 1})
        store.insert('items', {'foo': 2, 'bar': 2})
        docs = store.findall('items')
        self.assertEqual(len(docs), 2)
        doc = docs.pop()
        store.delete('items', '$foo = ?', (doc['foo'],))
        docs = store.findall('items')
        self.assertEqual(len(docs), 1)
        self.assertNotEqual(docs[0], doc)
        store.close()
        store.open(self.filename)
        docs = store.findall('items')
        self.assertEqual(len(docs), 1)
        self.assertNotEqual(docs[0], doc)

    def test_execute(self):
        """Ensure execute() works."""
        store = self.store
        store.create_index('items', '$foo')
        doc = {'foo': 1, 'bar': 2}
        store.insert('items', doc)
        docs = store.execute('SELECT _doc_ FROM items WHERE $foo = 1')
        assert json.loads(docs[0][0]) == doc


if __name__ == '__main__':
    unittest.main()
