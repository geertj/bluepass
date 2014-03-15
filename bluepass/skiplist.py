#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import math
import random

__all__ = ['SkipList']


# The following functions are debugging functions. They are available only when
# Python is not started with -O.

if __debug__:

    def fmtnode(node):
        """Format a single skiplist node."""
        level = max(1, len(node) - 3)
        skip = '(none)' if level == 1 else node[-1]
        return '<Node(level={}, key={}, value={}, skip={})>' \
                    .format(level, node[0], node[1], skip)

    def dump(sl):
        """Dump a skiplist to standard output."""
        print('== Dumping skiplist {0!r}'.format(sl))
        print('Level: {}/{}'.format(sl.level, sl.maxlevel))
        print('Size: {}/{}'.format(len(sl)))
        node = sl._head
        print('{0} (head)'.format(fmtnode(node)))
        node = node[2]
        while node is not sl._tail:
            print('{0}'.format(fmtnode(node)))
            node = node[2]
        print('{0} (tail)'.format(fmtnode(node)))
        print()

    def check(sl):
        """Check the internal structure of a skiplist."""
        level = sl.maxlevel
        assert level > 0
        while sl._head[1+level] is sl._tail and level > 1:
            level -= 1
        assert level == sl.level
        assert sl._head[0] is sl._head[1] is None
        assert sl._head[-1] == 0
        pos = 0
        prev, node = None, sl._head
        inbound = {id(sl._head): 0, id(sl._tail): len(sl)}
        while node is not sl._tail:
            assert isinstance(node, list)
            level = min(sl.level, max(1, len(node)-3))
            assert 1 <= level <= sl.maxlevel
            for i in range(1, level):
                fnode = node[2+i]
                flevel = min(sl.level, max(1, len(fnode)-3))
                if i == flevel-1:
                    inbound[id(fnode)] = pos
            if level > 1:
                assert id(node) in inbound
                assert pos == inbound[id(node)] + node[-1]
            for i in range(level):
                fnode = node[2+i]
                assert isinstance(fnode, list)
                level = max(1, len(node) - 3)
                assert level >= i+1
            prev, node = node, node[2]
            pos += 1
        assert sl._tail[0] is None
        assert sl._tail[1] is None
        for i in range(sl.maxlevel):
            assert sl._tail[2+i] is None
        assert len(sl) == inbound[id(sl._tail)] + node[-1]


class SkipList(object):
    """An indexable skip list.
    
    A SkipList provides an ordered sequence of (key, value) pairs. The list is
    always sorted on key and supports O(1) forward iteration. It has O(log N)
    time complexity for key lookup, pair insertion and pair removal anywhere in
    the list. The list also supports O(log N) element access by position.

    Skip lists were first described by William Pugh. See the following papers:
    
     * ftp://ftp.cs.umd.edu/pub/skipLists/skiplists.pdf (original paper)
     * http://drum.lib.umd.edu/bitstream/1903/544/2/CS-TR-2286.1.pdf (cookbook)
    
    This implementation has the following features:

     * Duplicate keys are allowed.
     * A "skip" count is kept for each node to implement efficient access by
       position. The skip count indicates how many nodes were skipped over by
       the highest level incoming link. This is different from the indexable
       skiplist described in the cookbook, because there is just one count per
       node, instead of a count at every level. Also the count is only stored
       for nodes with a level > 1, as it is always 1 for nodes at level 1.
    """

    # Kudos to http://pythonsweetness.tumblr.com/post/45227295342 for some
    # useful tricks, including using a list for the nodes to save memory.

    # Use the built-in Mersenne Twister random number generator. It is more
    # appropriate than SystemRandom because we don't need cryptographically
    # secure random numbers, and we don't want to do a system call to read
    # /dev/urandom for each random number we need (every insertion needs a new
    # random number).

    _rnd = random.Random()
    _rnd.seed(os.urandom(16))

    def __init__(self, default=None):
        """Create a new SkipList.

        The *default* parameter specifies the return value for :meth:`search`
        and :meth:`remove` that means "key not found". The default is ``None``,
        and can be changed to support adding pairs with a ``None`` value.
        """
        self.p = int((1<<31) / math.e)
        self.maxlevel = 20
        self.default = default
        self._level = 1
        self._head = self._make_node(self.maxlevel, None, None)
        self._tail = self._make_node(self.maxlevel, None, None)
        for i in range(self.maxlevel):
            self._head[2+i] = self._tail
        self._path = [None] * self.maxlevel
        self._distance = [None] * self.maxlevel

    @property
    def level(self):
        """The current level of the skip list."""
        return self._level

    def _random_level(self):
        # Exponential distribution as per Pugh's paper.
        l = 1
        maxlevel = min(self.maxlevel, self.level+1)
        while l < maxlevel and self._rnd.getrandbits(31) < self.p:
            l += 1
        return l

    def _make_node(self, level, key, value):
        # Node layout: [key, value, next*LEVEL, skip?]
        # The "skip" element indicates how many nodes are skipped by the
        # highest level incoming link.
        if level == 1:
            return [key, value, None]
        else:
            return [key, value] + [None]*level + [0]

    # The _find_* methods (ab)use _path and _distance as static variables so
    # that they don't have to allocate new lists every time.

    def _find_lt(self, key):
        # Find path to last node < key
        node = self._head
        distance = 0
        for i in reversed(range(self.level)):
            nnode = node[2+i]
            while nnode is not self._tail and nnode[0] < key:
                nnode, node = nnode[2+i], nnode
                distance += 1 if i == 0 else node[-1]
            self._path[i] = node
            self._distance[i] = distance
        return self._path, self._distance

    def _find_lte(self, key):
        # Find path to last node <= key
        node = self._head
        distance = 0
        for i in reversed(range(self.level)):
            nnode = node[2+i]
            while nnode is not self._tail and nnode[0] <= key:
                nnode, node = nnode[2+i], nnode
                distance += 1 if i == 0 else node[-1]
            self._path[i] = node
            self._distance[i] = distance
        return self._path, self._distance

    def _find_pos(self, pos):
        # Create path to node at pos.
        node = self._head
        distance = 0
        for i in reversed(range(self.level)):
            nnode = node[2+i]
            ndistance = distance + (1 if i == 0 else nnode[-1])
            while nnode is not self._tail and ndistance <= pos:
                nnode, node, distance = nnode[2+i], nnode, ndistance
                ndistance += 1 if i == 0 else nnode[-1]
            self._path[i] = node
            self._distance[i] = distance
        return self._path, self._distance

    def insert(self, key, value):
        """Insert the pair ``(key, value)``.

        Pairs with a duplicate key may be inserted, and insertion order will be
        preserved for these pairs.
        """
        node = self._make_node(self._random_level(), key, value)
        # If necessary, increase the level of the list.
        level = max(1, len(node) - 3)
        if level > self.level:
            self._tail[-1] = len(self)
            self._level = level
        # Find insertion point and update pointers
        path, distance = self._find_lte(key)
        for i in range(level):
            node[2+i] = path[i][2+i]
            path[i][2+i] = node
        if level > 1:
            node[-1] = 1 + distance[0] - distance[level-1]
        # Update skip counts
        node = node[2]
        i = 2; j = min(len(node) - 3, self.level)
        while i <= self.level:
            while j < i:
                node = node[i]
                j = min(len(node) - 3, self.level)
            node[-1] -= distance[0] - distance[j-1] if j <= level else -1
            i = j+1

    def replace(self, key, value):
        """Replace the value of a key-value pair.

        If a pair with *key* exists, then its value is updated to *value*. If
        no such pair exists, then nothing is done.

        If a value was replaced, return the old value. Otherwise return the
        default value.
        """
        path, _ = self._find_lt(key)
        node = path[0][2]
        if node is self._tail or node[0] != key:
            return self.default
        node[1], oldvalue = value, node[1]
        return oldvalue

    def remove(self, key):
        """Remove the first key-value pair with key *key*.

        If a pair was removed, return its value. Otherwise return the default
        value.
        """
        path, distance = self._find_lt(key)
        node = path[0][2]
        if node is self._tail or node[0] != key:
            return self.default
        level = max(1, len(node) - 3)
        # Remove the node from the list
        for i in range(level):
            path[i][2+i] = node[2+i]
        # Update distances
        value = node[1]
        node = node[2]
        i = 2; j = min(len(node) - 3, self.level)
        while i <= self.level:
            while j < i:
                node = node[i]
                j = min(len(node) - 3, self.level)
            node[-1] += distance[0] - distance[j-1] if j <= level else -1
            i = j+1
        # Reduce level if last node on current level was removed
        while self.level > 1 and self._head[1+self.level] is self._tail:
            self._level -= 1
            self._tail[-1] += self._tail[-1] - len(self)
        return value

    def search(self, key):
        """Find the first key-value pair with key *key*.

        If a pair was found, return its value. Otherwise return the default
        value.
        """
        path, _ = self._find_lt(key)
        node = path[0][2]
        if node is self._tail or node[0] != key:
            return self.default
        return node[1]

    def clear(self):
        """Remove all key-value pairs."""
        for i in range(self.maxlevel):
            self._head[2+i] = self._tail
            self._tail[-1] = 0
        self._level = 1

    def items(self, start=None, stop=None):
        """Return an iterator yielding pairs.

        If *start* is specified, iteration starts at the first pair with a key
        that is larger than or equal to *start*. If not specified, iteration
        starts at the first pair in the list.

        If *stop* is specified, iteration stops at the last pair that is
        smaller than *stop*. If not specified, iteration end with the last pair
        in the list.
        """
        if start is None:
            node = self._head[2]
        else:
            path, _ = self._find_lt(start)
            node = path[0][2]
        while node is not self._tail and (stop is None or node[0] < stop):
            yield (node[0], node[1])
            node = node[2]

    __iter__ = items

    def __len__(self):
        """Return the number of pairs in the list."""
        dist = 0
        idx = self.level + 1
        node = self._head[idx]
        while node is not self._tail:
            dist += node[-1] if idx > 2 else 1
            node = node[idx]
        dist += node[-1]
        return dist

    def __getitem__(self, pos):
        """Return a pair by its position.

        If *pos* is a slice, then return a generator that yields pairs as
        specified by the slice.
        """
        size = len(self)
        if isinstance(pos, int):
            if pos < 0:
                pos += size
            if not 0 <= pos < size:
                raise IndexError('index out of range')
            path, _ = self._find_pos(pos+1)
            node = path[0]
            return (node[0], node[1])
        elif isinstance(pos, slice):
            start, stop = pos.start, pos.stop
            if start is None:
                start = 0
            elif start < 0:
                start += size
            if stop is None:
                stop = size
            elif stop < 0:
                stop += size
            path, _ = self._find_pos(start+1)
            def genpairs():
                pos = start; node = path[0]
                while node is not self._tail and pos < stop:
                    yield (node[0], node[1])
                    node = node[2]; pos += 1
            return genpairs()
        else:
            raise TypeError('expecting int or slice, got {0.__name__!r}'.format(type(pos)))
