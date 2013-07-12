#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import bisect
import os.path


def iconpath(name):
    pkgdir = os.path.split(__file__)[0]
    path = os.path.join(pkgdir, 'icons', name)
    return path


## The "blist" package provides a list with better asymptotic insert()
## and remove() behavior for operations not at the end of the list.
#try:
#    from blist import blist as list
#except ImportError:
#    pass


class SortedList(object):
    """A SortedList is collection of keys/value pairs, where the keys have an
    ordering and where the pairs are stored in the list in that ordering.

    Keys do not need to be unique.
    """

    def __init__(self):
        self._keys = list()
        self._values = list()
        self._data = list()

    def find(self, key, value=None):
        """Find the pair with `key` and optionally `value` and return its
        index, or -1 if the pair was not found."""
        pos = bisect.bisect_left(self._keys, key)
        if value is not None:
            while pos < len(self._keys) and self._keys[pos] == key and \
                        self._values[pos] != value:
                pos += 1
            if pos == len(self._keys):
                return -1
        if pos == len(self._keys) or self._keys[pos] != key:
            return -1
        return pos

    def insert(self, key, value=None, data=None):
        """Insert the key/value pair. Return the position where the pair was
        inserted."""
        pos = bisect.bisect_right(self._keys, key)
        self._keys.insert(pos, key)
        self._values.insert(pos, value)
        self._data.insert(pos, data)
        return pos

    def remove(self, key, value=None):
        """Remove a key/value pair. Return the position where the pair was
        deleted, or -1 if the pair was not found."""
        pos = bisect.bisect_left(self._keys, key)
        if value is not None:
            while pos < len(self._keys) and self._keys[pos] == key and \
                        self._values[pos] != value:
                pos += 1
            if pos == len(self._keys):
                return -1
        if self._keys[pos] != key:
            return -1
        del self._keys[pos]
        del self._values[pos]
        del self._data[pos]

    def removeat(self, pos):
        """Remove the entry at `pos`."""
        del self._keys[pos]
        del self._values[pos]
        del self._data[pos]

    def keyat(self, pos):
        """Return the key at position `pos`."""
        return self._keys[pos]

    def valueat(self, pos):
        """Return the value at position `pos`."""
        return self._values[pos]

    def dataat(self, pos):
        """Return the extra data element at position `pos`."""
        return self._data[pos]

    def __len__(self):
        return len(self._keys)

    def __iter__(self):
        return iter(self._keys)

    iterkeys = __iter__

    def itervalues(self):
        return iter(self._values)

    def iterdata(self):
        return iter(self._data)
