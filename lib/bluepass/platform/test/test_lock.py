#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import os
import sys

from bluepass.test.unit import UnitTest, assert_raises
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
