#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import math
import random

from tests.support import *
from bluepass.skiplist import *
from bluepass import skiplist


class TestSkipList(UnitTest):
    """Unit test suite for SkipList."""

    def test_basic(self):
        """Ensure that a basic insert() works."""
        sl = SkipList()
        sl.insert('foo', 'bar')
        self.assertEqual(sl.search('foo'), 'bar')
        self.assertEqual(sl.remove('foo'), 'bar')
        self.assertIsNone(sl.remove('foo'))
        self.assertIsNone(sl.search('foo'))

    def test_search(self):
        """Ensure that search() works properly."""
        sl = SkipList()
        sl.insert('foo', 'bar')
        sl.insert('baz', 'qux')
        self.assertEqual(sl.search('foo'), 'bar')
        self.assertIsNone(sl.search('bar'))
        self.assertEqual(sl.search('baz'), 'qux')

    def test_search_duplicate_keys(self):
        """Ensure that search() can find duplicate keys."""
        sl = SkipList()
        sl.insert('foo', 'bar')
        sl.insert('foo', 'baz')
        self.assertEqual(sl.search('foo'), 'bar')

    def test_insert_duplicate_keys(self):
        """Ensure that insertion order is maintained for duplicate keys."""
        sl = SkipList()
        for i in range(100):
            sl.insert(0, i)
        self.assertEqual(list(sl), sorted(sl))
        sl = SkipList()
        for i in range(100):
            sl.insert(0, 99-i)
        self.assertEqual(list(sl), list(reversed(sorted(sl))))

    def test_remove_duplicate_keys(self):
        """Ensure that duplicate keys are removed left to right."""
        sl = SkipList()
        sl.insert('foo', 'bar')
        sl.insert('foo', 'baz')
        self.assertEqual(list(sl), [('foo', 'bar'), ('foo', 'baz')])
        self.assertEqual(sl.remove('foo'), 'bar')
        self.assertEqual(list(sl), [('foo', 'baz')])
        self.assertEqual(sl.remove('foo'), 'baz')
        self.assertEqual(list(sl), [])

    def test_replace(self):
        """Ensure that replace() works correctly."""
        sl = SkipList()
        sl.insert('foo', 'bar')
        self.assertIsNone(sl.replace('bar', 'baz'))
        self.assertEqual(sl.replace('foo', 'baz'), 'bar')
        sl.insert('foo', 'qux')
        self.assertIsNone(sl.replace('bar', 'baz'))
        self.assertEqual(sl.replace('foo', 'quux'), 'baz')
        self.assertEqual(list(sl), [('foo', 'quux'), ('foo', 'qux')])

    def test_clear(self):
        """Ensure that clear() works correctly."""
        sl = SkipList()
        sl.insert('bar', 'baz')
        sl.insert('foo', 'bar')
        self.assertEqual(list(sl), [('bar', 'baz'), ('foo', 'bar')])
        sl.clear()
        self.assertEqual(list(sl), [])
        skiplist.check(sl)

    def test_length(self):
        """Ensure that len() works correctly."""
        sl = SkipList()
        pairs = []
        for i in range(1000):
            pair = (random.randint(0, 10000), i)
            pairs.append(pair)
            sl.insert(*pair)
            self.assertEqual(len(sl), i+1)
        random.shuffle(pairs)
        for i,pair in enumerate(pairs):
            sl.remove(pair[0])
            self.assertEqual(len(sl), len(pairs)-i-1)

    def test_index(self):
        """Ensure that the skiplist can be indexed by position."""
        sl = SkipList()
        pairs = []
        for i in range(100):
            pair = (random.randint(0, 10000), i)
            pairs.append(pair)
            sl.insert(*pair)
        pairs = sorted(pairs)
        for pos in range(len(pairs)):
            self.assertEqual(sl[pos], pairs[pos])

    def test_index(self):
        """Ensure that the skiplist can be indexed from the end."""
        sl = SkipList()
        pairs = []
        for i in range(100):
            pair = (random.randint(0, 10000), i)
            pairs.append(pair)
            sl.insert(*pair)
        pairs = sorted(pairs)
        for pos in range(-len(pairs), len(pairs)):
            self.assertEqual(sl[pos], pairs[pos])

    def test_sorted(self):
        """Ensure that the list is sorted."""
        sl = SkipList()
        for i in range(100):
            sl.insert(random.randint(0, 10000), 0)
        self.assertEqual(list(sl), sorted(list(sl)))

    def test_iterate(self):
        """Ensure that iteration works."""
        sl = SkipList()
        for i in range(100):
            sl.insert(i, i)
        ref = list(zip(range(100), range(100)))
        self.assertEqual(list(sl), ref)
        self.assertEqual(list(sl.items()), ref)
        self.assertEqual(list(reversed(sl)), list(reversed(ref)))

    def test_iterate_start_stop(self):
        """Ensure that iteration "start" and "stop" arguments works."""
        sl = SkipList()
        for i in range(100):
            sl.insert(i, i)
        ref = list(zip(range(100), range(100)))
        self.assertEqual(list(sl), ref)
        self.assertEqual(list(sl.items()), ref)
        self.assertEqual(list(sl.items(start=10)), ref[10:])
        self.assertEqual(list(sl.items(start=10.1)), ref[11:])
        self.assertEqual(list(sl.items(start=11)), ref[11:])
        self.assertEqual(list(sl.items(stop=90)), ref[:90])
        self.assertEqual(list(sl.items(stop=90.1)), ref[:91])
        self.assertEqual(list(sl.items(stop=91)), ref[:91])
        self.assertEqual(list(sl.items(start=10, stop=90)), ref[10:90])
        self.assertEqual(list(sl.items(start=10.1, stop=90)), ref[11:90])
        self.assertEqual(list(sl.items(start=10, stop=90.1)), ref[10:91])
        self.assertEqual(list(sl.items(start=10.1, stop=90.1)), ref[11:91])

    def test_slice(self):
        """Ensure indexing with a slice works."""
        sl = SkipList()
        for i in range(100):
            sl.insert(i, i)
        ref = list(zip(range(100), range(100)))
        self.assertEqual(list(sl), ref)
        self.assertEqual(list(sl[:10]), ref[:10])
        self.assertEqual(list(sl[10:]), ref[10:])
        self.assertEqual(list(sl[10:90]), ref[10:90])
        self.assertEqual(list(sl[:]), ref)

    def test_default(self):
        """Test that the default value can be changed."""
        sl = SkipList(default=-1)
        sl.insert('foo', 'bar')
        self.assertEqual(sl.search('baz'), -1)
        sl.insert('baz', None)
        self.assertIsNone(sl.search('baz'))
        self.assertIsNone(sl.remove('baz'))
        self.assertEqual(sl.remove('baz'), -1)

    def test_many_pairs(self):
        """Perform stress testing with 10,000 pairs."""
        sl = SkipList()
        pairs = []
        # Insert up to 10,000 unique random keys with distinct values
        for i in range(10000):
            pair = (random.randint(0, 2<<31), i)
            if sl.search(pair[0]) is not None:
                continue
            sl.insert(*pair)
            pairs.append(pair)
            if i % 500 == 0:
                skiplist.check(sl)
        skiplist.check(sl)
        random.shuffle(pairs)
        for pair in pairs:
            self.assertEqual(sl.search(pair[0]), pair[1])
        random.shuffle(pairs)
        remove = len(pairs)//2
        for i in range(0, remove):
            self.assertEqual(sl.remove(pairs[i][0]), pairs[i][1])
            if i % 500 == 0:
                skiplist.check(sl)
        skiplist.check(sl)
        del pairs[:remove]
        for pair in pairs:
            self.assertEqual(sl.search(pair[0]), pair[1])
        skiplist.check(sl)
        fanout = (1<<31) / sl.p
        self.assertGreater(sl.level, math.log(len(pairs), fanout)-2)


if __name__ == '__main__':
    unittest.main()
