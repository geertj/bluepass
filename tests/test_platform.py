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
import time
import signal
import stat

from gruvi.socketpair import socketpair

from support import *
from bluepass import platform


class TestPlatform(UnitTest):

    def test_lock_basic(self):
        # Ensure that a basic lock + unlock works.
        fname = self.tempname()
        lock = platform.lock_file(fname)
        platform.unlock_file(lock)

    def test_lock_multiple(self):
        # Lock + unlock a lock multiple times.
        fname = self.tempname()
        lock = platform.lock_file(fname)
        platform.unlock_file(lock)
        lock = platform.lock_file(fname)
        platform.unlock_file(lock)

    @unix_only
    def test_lock_locked_unix(self):
        # Lock a lock that is already locked. This should raise an OSError.
        fname = self.tempname()
        pid = os.fork()
        # The locks are per process. So need to fork here.
        if pid == 0:
            # child
            lock = platform.lock_file(fname)
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                pass
            platform.unlock_file(lock)
            os._exit(0)
        time.sleep(0.1)
        self.assertRaises(OSError, platform.lock_file, fname)
        # Exit the child now, which will release the lock
        os.kill(pid, signal.SIGINT)
        os.waitpid(pid, 0)
        lock = platform.lock_file(fname)
        platform.unlock_file(lock)

    @unix_only
    def test_get_homedir_unix(self):
        # Ensure that get_homedir() works with and without $HOME
        oldhome = os.environ.pop('HOME')
        os.environ['HOME'] = self.tempdir
        self.assertEqual(platform.get_homedir(), self.tempdir)
        del os.environ['HOME']
        import pwd
        self.assertEqual(platform.get_homedir(), pwd.getpwuid(os.getuid()).pw_dir)
        if oldhome is not None:
            os.environ['HOME'] = oldhome

    @unix_only
    def test_get_appdir_unix(self):
        # Ensure that get_appdir() returns something that exists and is below
        # get_homedir()
        oldhome = os.environ.pop('HOME')
        os.environ['HOME'] = self.tempdir
        appdir = platform.get_appdir('foo')
        self.assertTrue(appdir.startswith(platform.get_homedir()))
        st = os.stat(appdir)
        self.assertTrue(stat.S_ISDIR(st.st_mode))
        if oldhome is not None:
            os.environ['HOME'] = oldhome

    @unix_only
    def test_disable_debugging(self):
        # Ensure that disable_debugging() works.
        pid = os.fork()
        if pid == 0:
            # child
            platform.disable_debugging()
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                pass
            os._exit(0)
        time.sleep(0.1)
        if sys.platform.startswith('linux'):
            st = os.stat('/proc/{0}/mem'.format(pid))
            self.assertEqual(st.st_uid, 0)
        else:
            raise AssertionError('test not implemented for {!r}'.format(sys.platform))
        os.kill(pid, signal.SIGINT)
        os.waitpid(pid, 0)

    def test_get_process_info(self):
        # Ensure that get_process_info() called for oud pid returns information
        # about ourselves.
        pinfo = platform.get_process_info(os.getpid())
        self.assertIsInstance(pinfo, tuple)
        self.assertEqual(pinfo.exe, os.path.realpath(sys.executable))
        self.assertEqual(pinfo.cmdline[1:], sys.argv)
        if hasattr(os, 'getuid'):
            self.assertEqual(pinfo.uid, os.getuid())
        if hasattr(os, 'getgid'):
            self.assertEqual(pinfo.gid, os.getgid())

    def test_get_peer_info(self):
        # Ensure that get_peer_info() when called for a connected socket that
        # we created returns information about ourselves.
        s1, s2 = socketpair()
        pinfo = platform.get_peer_info(s1.getsockname(), s1.getpeername())
        self.assertIsInstance(pinfo, tuple)
        self.assertEqual(pinfo.exe, os.path.realpath(sys.executable))
        self.assertEqual(pinfo.cmdline[1:], sys.argv)
        if hasattr(os, 'getuid'):
            self.assertEqual(pinfo.uid, os.getuid())
        if hasattr(os, 'getgid'):
            self.assertEqual(pinfo.gid, os.getgid())
        s1.close()
        s2.close()


if __name__ == '__main__':
    unittest.main()
