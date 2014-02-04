#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from tests.support import *
from bluepass.database import *


class TestDatabase(UnitTest):
    """Unit test suite for Database."""

    def setUp(self):
        self.filename = self.tempname()
        self.database = Database(self.filename)
        self.database.create_table('items')

    def tearDown(self):
        self.database.close()

    def test_open_close(self):
        db = self.database
        d1 = { 'id': 1, 'foo': 'bar' }
        db.insert('items', d1)
        docs = db.findall('items')
        assert d1 in docs
        assert len(docs) == 1
        db.close()
        db.open(self.filename)
        docs = db.findall('items')
        assert d1 in docs
        assert len(docs) == 1

    def test_find_str(self):
        db = self.database
        db.insert('items', {'foo': 'bar'})
        db.insert('items', {'foo': 'baz'})
        docs = db.findall('items', '$foo=?', ('bar',))
        assert len(docs) == 1
        assert docs[0]['foo'] == 'bar'

    def test_find_int(self):
        db = self.database
        db.insert('items', {'foo': 1})
        db.insert('items', {'foo': 2})
        docs = db.findall('items', '$foo=?', (1,))
        assert len(docs) == 1
        assert docs[0]['foo'] == 1

    def test_find_int_gt(self):
        db = self.database
        db.insert('items', {'foo': 1})
        db.insert('items', {'foo': 2})
        docs = db.findall('items', '$foo>?', (1,))
        assert len(docs) == 1
        assert docs[0]['foo'] == 2

    def test_find_or(self):
        db = self.database
        db.insert('items', {'foo': 1})
        db.insert('items', {'foo': 2})
        docs = db.findall('items', '$foo=? OR $foo=?', (1,2))
        assert len(docs) == 2
        assert docs[0]['foo'] in (1, 2)
        assert docs[1]['foo'] in (1, 2)

    def test_find_and(self):
        db = self.database
        db.insert('items', {'foo': 1, 'bar': 1})
        db.insert('items', {'foo': 2, 'bar': 1})
        docs = db.findall('items', '$foo=? AND $bar=?', (1,1))
        assert len(docs) == 1
        assert docs[0]['foo'] == 1
        assert docs[0]['bar'] == 1

    def test_find_nested(self):
        db = self.database
        db.insert('items', {'foo': {'bar': 1}})
        db.insert('items', {'foo': {'bar': 2}})
        docs = db.findall('items', '$foo$bar=?', (1,))
        assert len(docs) == 1
        assert docs[0]['foo']['bar'] == 1

    def test_find_with_index(self):
        db = self.database
        db.create_index('items', '$foo', 'INTEGER', True)
        db.insert('items',{'foo': 1})
        db.insert('items',{'foo': 2})
        docs = db.findall('items','$foo==?', (1,))
        assert len(docs) == 1
        assert docs[0]['foo'] == 1

    def test_open_close_with_index(self):
        db = self.database
        db.create_index('items', '$foo', 'INTEGER', True)
        db.insert('items', {'foo': 1})
        db.insert('items', {'foo': 2})
        db.close()
        db.open(self.filename)
        docs = db.findall('items', '$foo==?', (1,))
        assert len(docs) == 1
        assert docs[0]['foo'] == 1

    def test_findone(self):
        db = self.database
        db.insert('items', {'foo': 1, 'bar': 1})
        db.insert('items', {'foo': 2, 'bar': 1})
        doc = db.findone('items', '$foo = 1')
        assert doc['foo'] == 1
        doc = db.findone('items', '$bar = 1')
        assert doc['bar'] == 1
        doc = db.findone('items', '$bar = 2')
        assert doc is None

    def test_insert_many(self):
        db = self.database
        db.insert_many('items', [{'foo': 1}, {'foo': 2}])
        docs = db.findall('items')
        assert len(docs) == 2

    def test_update(self):
        db = self.database
        db.insert('items', {'foo': 1, 'bar': 1})
        db.insert('items', {'foo': 2, 'bar': 2})
        docs = db.findall('items', '$bar=2')
        assert len(docs) == 1
        assert docs[0] == {'foo': 2, 'bar': 2 }
        doc = docs[0]
        doc['bar'] = 3
        db.update('items', '$foo = ?', (2,), doc)
        docs = db.findall('items')
        assert len(docs) == 2
        doc = db.findone('items', '$bar=3')
        assert doc == {'foo': 2, 'bar': 3}

    def test_update_with_index(self):
        db = self.database
        db.create_index('items', '$foo', 'INTEGER', True)
        db.create_index('items', '$bar', 'INTEGER', True)
        db.insert('items', {'foo': 1, 'bar': 1})
        db.insert('items', {'foo': 2, 'bar': 2})
        docs = db.findall('items', '$bar=2')
        assert len(docs) == 1
        assert docs[0] == {'foo': 2, 'bar': 2 }
        doc = docs[0]
        doc['bar'] = 3
        db.update('items', '$foo=?', (2,), doc)
        docs = db.findall('items')
        assert len(docs) == 2
        doc = db.findone('items', '$bar=3')
        assert doc == {'foo': 2, 'bar': 3}

    def test_delete(self):
        db = self.database
        db.insert('items', {'foo': 1, 'bar': 1})
        db.insert('items', {'foo': 2, 'bar': 2})
        docs = db.findall('items')
        assert len(docs) == 2
        doc = docs.pop()
        db.delete('items', '$foo = ?', (doc['foo'],))
        docs = db.findall('items')
        assert len(docs) == 1
        assert docs[0] != doc


if __name__ == '__main__':
    unittest.main()
