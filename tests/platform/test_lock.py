#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import sys

from ..unit import UnitTest, assert_raises
from bluepass.platform import lock_file, unlock_file, LockError


class TestLock(UnitTest):

    def test_lock_unlock(self):
        fname = self.tempfile()
        lock = lock_file(fname)
        unlock_file(lock)

    def test_lock_multiple(self):
        fname = self.tempfile()
        lock = lock_file(fname)
        # The tests below would require flock() on Posix which does per-fd
        # locking instead of lockf() which is per process. However flock() is
        # not safe on NFS on all platforms. So disable these tests.
        #err = assert_raises(LockError, lock_file, fname)
        #assert hasattr(err, 'lock_pid')
        #assert err.lock_pid == os.getpid()
        #assert hasattr(err, 'lock_uid')
        #assert err.lock_uid == os.getuid()
        #assert hasattr(err, 'lock_cmd')
        #assert sys.argv[0].endswith(err.lock_cmd)
        unlock_file(lock)
        lock = lock_file(fname)
        unlock_file(lock)
