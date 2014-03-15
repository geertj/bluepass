#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function, division

import sys
import time
import random

from tests.support import *
from bluepass.skiplist import *


class PerfSkipList(PerformanceTest):
    """Performance tests for our skiplist."""

    def _create_skiplist(self, n):
        """Create a skiplist with *n* elements."""
        sl = SkipList()
        maxkey = 100*n
        for i in range(n):
            sl.insert(random.randint(0, maxkey), i)
        return sl

    def _create_workload(self, sl, n):
        """Create a workload with *n* items."""
        pairs = []
        maxkey = 100*len(sl)
        for i in range(n):
            pair = (random.randint(0, maxkey), i)
            pairs.append(pair)
        return pairs

    def perf_search_throughput(self):
        """Test search() throughput."""
        for logN in range(3, 6):
            items = 10**logN
            sl = self._create_skiplist(items)
            pairs = list(sl)
            random.shuffle(pairs)
            load = pairs[0:int(0.2*len(sl))]
            count = 0
            t0 = t1 = time.time()
            while count < len(load) and t1 - t0 < 1:
                sl.search(load[count][0])
                count += 1
                if count%100 == 0:
                    t1 = time.time()
            throughput = count / (t1 - t0)
            self.add_result(throughput, params={'logN': logN})

    def perf_insert_throughput(self):
        """Test insert() throughput."""
        for logN in range(3, 6):
            items = 10**logN
            sl = self._create_skiplist(items)
            load = self._create_workload(sl, int(0.2*len(sl)))
            count = 0
            t0 = t1 = time.time()
            while count < len(load) and t1 - t0 < 1:
                sl.insert(*load[count])
                count += 1
                if count%100 == 0:
                    t1 = time.time()
            throughput = count / (t1 - t0)
            self.add_result(throughput, params={'logN': logN})

    def perf_remove_throughput(self):
        """Test remove() throughput."""
        for logN in range(3, 6):
            items = 10**logN
            sl = self._create_skiplist(items)
            pairs = list(sl)
            random.shuffle(pairs)
            load = pairs[0:int(0.2*len(sl))]
            count = 0
            t0 = t1 = time.time()
            while count < len(load) and t1 - t0 < 1:
                sl.remove(load[count][0])
                count += 1
                if count%100 == 0:
                    t1 = time.time()
            throughput = count / (t1 - t0)
            self.add_result(throughput, params={'logN': logN})

    def perf_index_throughput(self):
        """Test throughput of indexed access."""
        for logN in range(3, 6):
            items = 10**logN
            sl = self._create_skiplist(items)
            load = random.sample(range(items), int(0.2*len(sl)))
            count = 0
            t0 = t1 = time.time()
            while count < len(load) and t1 - t0 < 1:
                sl[load[count]]
                count += 1
                if count%100 == 0:
                    t1 = time.time()
            throughput = count / (t1 - t0)
            self.add_result(throughput, params={'logN': logN})

    def perf_memory_overhead(self):
        """Test memory overhead."""
        for logN in range(3, 6):
            items = 10**logN
            sl = self._create_skiplist(items)
            node = sl._head[2]
            extrasize = 0
            while node is not sl._tail:
                extrasize += sys.getsizeof(node)
                if  len(node) > 3:
                    extrasize += sys.getsizeof(node[-1])
                node = node[2]
            overhead = extrasize / len(sl)
            self.add_result(overhead, params={'logN': logN})


if __name__ == '__main__':
    unittest.defaultTestLoader.testMethodPrefix = 'perf'
    unittest.main()
