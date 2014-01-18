#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import re
import sys
import json
import sqlite3
import logging
from datetime import datetime

from bluepass.errors import *
from bluepass import platform


def _get_json_value(obj, path):
    """Get a value from a JSON object."""
    for key in path[1:].split('$'):
        child = obj.get(key)
        if child is None:
            return
        obj = child
    return obj

def get_json_value(doc, path):
    """Get a value from a JSON document."""
    obj = json.loads(doc)
    return _get_json_value(obj, path)


class DatabaseError(Error):
    """Database error."""


class Database(object):
    """Our central data store.

    This is a SQLite database that stores JSON documents. Some document
    database like functionality is provided.
    """

    sqlite_args = { 'timeout': 2 }

    def __init__(self, fname=None, **sqlite_args):
        """Constructor."""
        self.filename = None
        self._lock = None
        self.sqlite_args = self.sqlite_args  # move from class to instance
        self.sqlite_args.update(sqlite_args)
        if fname is not None:
            self.open(fname)

    def open(self, fname):
        """Open the database if it is not opened yet."""
        if self.filename is not None:
            raise RuntimeError('Database already opened.')
        self.connection = sqlite3.connect(fname, **self.sqlite_args)
        self.connection.create_function('get_json_value', 2, get_json_value)
        self.filename = fname
        self._load_schema()

    def _cursor(self):
        """Return a new cursor."""
        return self.connection.cursor()

    def _commit(self, cursor):
        """Commit and close a cursor."""
        if cursor.connection is not self.connection:
            raise RuntimeError('Cursor does not belong to this store')
        self.connection.commit()
        cursor.close()

    def _load_schema(self):
        """INTERNAL: load information on indices and tables."""
        cursor = self._cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        tables = [ row[0] for row in cursor.fetchall() ]
        indices = {}
        for table in tables:
            cursor.execute("PRAGMA index_list('%s')" % table)
            indices[table] = [ row[1][2+len(table):] for row in cursor.fetchall() ]
        self._commit(cursor)
        self.tables = tables
        self.indices = indices

    def create_table(self, table):
        """INTERNAL: create a table."""
        cursor = self._cursor()
        cursor.execute('CREATE TABLE %s (doc TEXT)' % table)
        self.tables.append(table)
        self.indices[table] = []
        self._commit(cursor)

    def create_index(self, table, path, typ, unique):
        cursor = self._cursor()
        """Create a new index."""
        cursor.execute('ALTER TABLE %s ADD COLUMN _%s %s' % (table, path, typ))
        unique = 'UNIQUE' if unique else ''
        cursor.execute('CREATE %s INDEX _%s_%s ON %s(_%s)' % (unique, table, path, table, path))
        cursor.execute("UPDATE %s SET _%s = get_json_value(doc, '%s')" % (table, path, path))
        self.indices[table].append(path)
        self._commit(cursor)

    def lock(self):
        """Lock the database."""
        # I would have loved to use SQLite based locking but it seems
        # impossible to have a cross-connection and cross-transaction write
        # lock while still allowing reads from other connections (for e.g.
        # backups and getting lock information).
        lockname = '%s-lock' % self.filename
        try:
            self._lock = platform.lock_file(lockname)
        except platform.LockError as e:
            msg = 'Database is locked by process %d (%s)' % (e.lock_pid, e.lock_cmd)
            raise DatabaseError(msg)
        except Exception as e:
            raise DatabaseError(str(e))

    def unlock(self):
        """Unlock the database."""
        if not self._lock:
            return
        platform.unlock_file(self._lock)
        self._lock = None

    def close(self):
        """Close the connection to the document store. This also unlocks the database."""
        if self.connection is None:
            return
        self.connection.close()
        self.connection = None
        self.unlock()
        self.filename = None

    _pathref = re.compile(r'(?:\$[a-z_][a-z0-9_]*)+', re.I)

    def _update_references(self, query, table):
        """INTERNAL: Update $path references in `query'. This replaces the
        references with either an index, if it exists, or a call to the
        get_json_value() stored procedure."""
        offset = 0
        for match in self._pathref.finditer(query):
            ref = match.group(0)
            if ref in self.indices[table]:
                repl = '_%s' % ref
            else:
                repl = "get_json_value(doc, '%s')" % ref
            query = query[:match.start(0)+offset] + repl + query[match.end(0)+offset:]
            offset += len(repl) - len(ref)
        return query

    def execute(self, table, query, args=()):
        """Execute a direct SQL query on the database."""
        cursor = self._cursor()
        query = self._update_references(query, table)
        cursor.execute(query, args)
        result = cursor.fetchall()
        self._commit(cursor)
        return result

    def findall(self, table, where=None, args=(), sort=None):
        """Find a set of documents in a collection."""
        cursor = self._cursor()
        query = 'SELECT doc FROM %s' % table
        if where is not None:
            query += ' WHERE %s' % where
        if sort is not None:
            query += ' ORDER BY %s' % sort
        query = self._update_references(query, table)
        result = cursor.execute(query, args)
        result = [ json.loads(row[0]) for row in result ]
        self._commit(cursor)
        return result

    def findone(self, table, where=None, args=(), sort=None):
        """Like findall() but only return the first result. In case there were
        no results, this returns None."""
        result = self.findall(table, where, args, sort)
        if result:
            return result[0]

    def insert(self, table, document):
        """Insert a document into a table."""
        cursor = self._cursor()
        cursor.execute('INSERT INTO %s (doc) VALUES (?)' % table, (json.dumps(document),))
        if self.indices[table]:
            cols = [ "_%s = get_json_value(doc, '%s')" % (ix, ix) for ix in self.indices[table] ]
            query = 'UPDATE %s SET %s WHERE _rowid_ = ?' % (table, ', '.join(cols))
            cursor.execute(query, (cursor.lastrowid,))
        self._commit(cursor)

    def insert_many(self, table, documents):
        """Insert many documents."""
        cursor = self._cursor()
        for doc in documents:
            cursor.execute('INSERT INTO %s (doc) VALUES (?)' % table, (json.dumps(doc),))
            if not self.indices[table]:
                continue
            cols = [ "_%s = get_json_value(doc, '%s')" % (ix, ix) for ix in self.indices[table] ]
            query = 'UPDATE %s SET %s WHERE _rowid_ = ?' % (table, ', '.join(cols))
            cursor.execute(query, (cursor.lastrowid,))
        self._commit(cursor)

    def delete(self, table, where, args):
        """INTERNAL: delete a document."""
        cursor = self._cursor()
        query = 'DELETE FROM %s' % table
        query += ' WHERE %s' % where
        query = self._update_references(query, table)
        cursor.execute(query, args)
        self._commit(cursor)

    def update(self, table, where, args, document):
        """Update an existing document."""
        cursor = self._cursor()
        query = 'SELECT _rowid_ FROM %s WHERE %s' % (table, where)
        query = self._update_references(query, table)
        result = cursor.execute(query, args)
        for res in result:
            query = 'UPDATE %s SET doc = ? WHERE _rowid_ = ?' % table
            args = (json.dumps(document), res[0])
            cursor.execute(query, args)
            if not self.indices[table]:
                continue
            cols = [ "_%s = get_json_value(doc, '%s')" % (ix, ix) for ix in self.indices[table] ]
            query = 'UPDATE %s SET %s WHERE _rowid_ = ?' % (table, ', '.join(cols))
            cursor.execute(query, (res[0],))
        self._commit(cursor)
