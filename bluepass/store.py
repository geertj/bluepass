#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import re
import json
import sqlite3
from contextlib import contextmanager

from bluepass.errors import *
from bluepass import platform

__all__ = ['Store', 'StoreError']


def get_json_value(doc, path):
    """Get a value from a JSON document.

    The *doc* argument must be a string containing a JSON document. The *path*
    argument is a '$' separated path name.
    """
    obj = json.loads(doc)
    for key in path[1:].split('$'):
        child = obj.get(key)
        if child is None:
            return
        obj = child
    return obj


StoreError = sqlite3.Error


class Store(object):
    """A simple JSON document store based on SQLite.

    The purpose of this class is to faciliate storing and retrieving JSON
    documents in SQLite. It specifically is not an ORM, and the fact that an
    SQL database is used internally intentionally leaks through in numerous
    places in the API. SQL is an excellent DSL for data access and there is no
    need to put something else on top. For example, the *where* argument to
    :meth:`findone` is a straight SQL WHERE clause.

    The store exposes zero or more collections, where each collection is a
    named set of documents. At the SQL level, a collection is a table with the
    same name as the collection. The table contains a column named _doc_ that
    contains the JSON document as a string.

    Collections can have an indices on values in the documents that are
    addressed by a path. The indexed values are stored in a separate column
    named after the path as _path_. In case a path does not exist in a
    document, NULL is stored. A path is of the format "$part1$part2..." where
    each part addresses a key in a JSON object (positional access inside a JSON
    array is not currently supported).

    In most cases, the document level API i.e. :meth:`insert`, :meth:`update`
    and :meth:`delete` should be used. These methods automatically serialize
    and de-serialize the JSON, and handle the indices transparently.

    There are cases however in which using the document level API would be
    inefficient, for example, when you need GROUP BY or aggregate functions
    like MAX. For these cases, the :meth:`execute` method is available that
    allows you to execute a direct SQL query. Note however that when using this
    method you need to serialize and de-serialize the JSON yourself, and you
    also need to deal with indexes manually.
    """

    default_sqlite_args = { 'timeout': 5, 'isolation_level': 'DEFERRED' }

    def __init__(self, fname=None, sqlite_args={}):
        """Constructor."""
        self._filename = None
        self._lock = None
        self._sqlite_args = self.default_sqlite_args.copy()
        self._sqlite_args.update(sqlite_args)
        self._connection = None
        self._tables = []
        self._indices = {}
        if fname is not None:
            self.open(fname)

    @property
    def filename(self):
        """The store file that is currently open."""
        return self._filename

    @property
    def collections(self):
        """A list with all collections."""
        return self._collections

    @property
    def indices(self):
        """A dictionary mapping each collection to its indices."""
        return self._indices

    def open(self, fname, lock=True):
        """Open the store file *fname*.

        If lock is *True* (the default), then the store file is locked using a
        platform specific file locking routine before it is opened.
        """
        if self._connection is not None:
            raise RuntimeError('document store already opened')
        self._filename = fname
        if lock:
            self._lock = platform.lock_file(self._filename)
        self._connection = sqlite3.connect(fname, **self._sqlite_args)
        self._connection.create_function('get_json_value', 2, get_json_value)
        self._load_schema()
        self._depth = 0

    def close(self):
        """Close the store file, and unlock it if it was locked."""
        if self._connection is None:
            return
        self._connection.close()
        self._connection = None
        if self._lock:
            platform.unlock_file(self._lock)
            self._lock = None
        self._filename = None

    def _load_schema(self):
        """Load information on collections and indices."""
        cursor = self._connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        collections = []
        indices = {}
        for coll in cursor.fetchall():
            collections.append(coll[0])
            cursor.execute("PRAGMA index_list('%s')".format(coll[0]))
            indices[coll[0]] = [ix[1][len(coll[0])+2:] for ix in cursor.fetchall()]
        cursor.close()
        self._collections = collections
        self._indices = indices
 
    @contextmanager
    def begin(self):
        """Begin a new transaction if none has been started yet.

        This method returns a context manager that will yield the cursor, and
        commit the transaction when the block exits, IFF the transaction was
        started by this context manager. This allows nesting of multiple begin
        blocks with the result that the last one to exit will commit.

        All methods in :class:`Store` that access the database use this method
        to get a cursor. This means that you can force multiple method calls to
        be executed in a single transaction by grouping them in a single ``with
        begin()`` block.
        """
        cursor = self._connection.cursor()
        self._depth += 1
        yield cursor
        self._depth -= 1
        if self._depth == 0:
            self._connection.commit()

    def create_collection(self, name):
        """Create a new collection *name*."""
        with self.begin() as cursor:
            cursor.execute("CREATE TABLE {0} (_doc_ TEXT)".format(name))
        self.collections.append(name)
        self.indices[name] = []

    _re_path = re.compile('(?<!_)((\$[a-zA-Z_][a-zA-Z0-9_]*)+)(?!\$)')

    def create_index(self, collection, path, valuetype='TEXT', modifier=''):
        """Create a new index on a collection.

        The index is created on the '$' separated JSON path *path*. The
        *valuetype* parameter specifies the type of the values in the index.
        The *modifier* argument adds an index modifier, for example to create a
        UNIQUE index. See the SQLite documention for a list of valid value
        types and index modifiers.
        """
        if not self._re_path.match(path):
            raise ValueError('illegal path: {0!r}'.format(path))
        with self.begin() as cursor:
            cursor.execute("ALTER TABLE {0} ADD COLUMN _{1}_ {2}"
                            .format(collection, path, valuetype))
            cursor.execute("CREATE {0} INDEX _{1}_{2} ON {1}(_{2}_)"
                            .format(modifier, collection, path))
            cursor.execute("UPDATE {0} SET _{1}_ = get_json_value(_doc_, '{1}')"
                            .format(collection, path))
        self.indices[collection].append(path)

    def _update_references(self, query, collection):
        """Update $path references in *query*.
        
        This replaces the paths with either an index reference or a call to the
        get_json_value() stored procedure.
        """
        indices = self.indices[collection]
        def replace(match):
            path = match.group(0)
            tmpl = '_{0}_' if path in indices else "get_json_value(_doc_, '{0}')"
            return tmpl.format(path)
        return self._re_path.sub(replace, query)

    def execute(self, query, args=()):
        """Execute a direct SQL query on the underlying database.

        Note: $path expansion is performed on the query, but it is always
        assumed that the path is indexed.
        """
        query = self._re_path.sub('_\\1_', query)
        with self.begin() as cursor:
            cursor.execute(query, args)
            result = cursor.fetchall()
        return result

    def findall(self, collection, where=None, args=(), sort=None):
        """Find all matching documents in a collection.

        The *where* argument, if provided, must be a SQL WHERE clause that
        selects the documents of interest. The where clause may contain $path
        references, which are expaned to either an index reference or to a call
        to a user defined function that parses the JSON and extracts the value.
        If no where clause is given, then all documents are selected.

        The *args* argument must be a tuple containing the values of the
        template parameters in *where*. Note that SQLite uses ``'?'`` style
        parameter passing.

        The *sort* argument, if provided, generates an ORDER BY clause in the
        SQL query.

        The return value is a list of parsed JSON documents.
        """
        query = "SELECT _doc_ FROM {0}".format(collection)
        if where is not None:
            query += " WHERE {0}".format(where)
        if sort is not None:
            query += " ORDER BY {0}".format(sort)
        query = self._update_references(query, collection)
        with self.begin() as cursor:
            cursor.execute(query, args)
            result = [json.loads(row[0]) for row in cursor.fetchall()]
        return result

    def findone(self, collection, where=None, args=(), sort=None):
        """Like :meth:`findall` but only return the first result, or None."""
        result = self.findall(collection, where, args, sort)
        if result:
            return result[0]

    def insert(self, collection, document):
        """Insert a document into a collection.

        Index columns are automatically updated.
        """
        doc = json.dumps(document)
        with self.begin() as cursor:
            cursor.execute("INSERT INTO {0} (_doc_) VALUES (?)".format(collection), (doc,))
            indices = self.indices[collection]
            if not indices:
                return
            assign = ["_{0}_ = get_json_value(_doc_, '{0}')".format(ix) for ix in indices]
            query = "UPDATE {0} SET {1} WHERE _rowid_ = ?".format(collection, ', '.join(assign))
            cursor.execute(query, (cursor.lastrowid,))

    def delete(self, collection, where, args=()):
        """Delete a document from a collection.

        This method returns the number of documents deleted.
        """
        query = "DELETE FROM {0} WHERE {1}".format(collection, where)
        query = self._update_references(query, collection)
        with self.begin() as cursor:
            cursor.execute(query, args)
            return cursor.rowcount

    def update(self, collection, document, where, args=()):
        """Update a document in a collection.

        The *where* and *args* parameters select the document to update. See
        :meth:`findall` for a description. Care should be taken that these
        unique identify the document to update.
        """
        with self.begin() as cursor:
            self.delete(collection, where, args)
            self.insert(collection, document)
