#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import sys
import shutil
import tempfile
import logging
import subprocess
import functools
import ssl

if sys.version_info[:2] >= (2,7):
    import unittest
else:
    import unittest2 as unittest

SkipTest = unittest.SkipTest

from gruvi.endpoints import create_ssl_context

__all__ = ['TestCase', 'UnitTest', 'PerformanceTest', 'MemoryTest', 'SkipTest',
           'unittest', 'unix_only']


def get_log_level():
    """Return the log level to be used when running tests.

    The log level is determined by $DEBUG and $VERBOSE.
    """
    debug = int(os.environ.get('DEBUG', '0'))
    verbose = int(os.environ.get('VERBOSE', '1'))
    if debug:
        return logging.DEBUG
    return 10 * max(0, 5 - verbose)


def setup_logging():
    """Configure a logger to output to stdout."""
    logger = logging.getLogger()
    if logger.handlers:
        return
    logger.setLevel(get_log_level())
    handler = logging.StreamHandler(sys.stdout)
    template = '%(levelname)s %(message)s'
    handler.setFormatter(logging.Formatter(template))
    logger.addHandler(handler)


def create_ssl_certificate(fname):
    """Create a new SSL private key and self-signed certificate, and store
    them both in the file *fname*."""
    try:
        openssl = subprocess.Popen(['openssl', 'req', '-new',
                        '-newkey', 'rsa:1024', '-x509', '-subj', '/CN=test/',
                        '-days', '365', '-nodes', '-batch',
                        '-out', fname, '-keyout', fname],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        sys.stderr.write('Error: openssl not found. SSL tests disabled.\n')
        return
    stdout, stderr = openssl.communicate()
    if openssl.returncode:
        sys.stderr.write('Error: key generation failed\n')
        sys.stderr.write('openssl stdout: {0}\n'.format(stdout))
        sys.stderr.write('openssl stderr: {0}\n'.format(stderr))


def unix_only(func):
    """Decorator to mark a test as Unix-only."""
    @functools.wraps(func)
    def wrapped(self):
        if not hasattr(os, 'fork'):
            raise SkipTest('this test only works on Unix')
        return func(self)
    return wrapped


class TestCase(unittest.TestCase):
    """Base class for test suites."""

    @classmethod
    def setUpClass(cls):
        setup_logging()
        cls.testdir = os.path.abspath(os.path.split(__file__)[0])
        cls.topdir = os.path.split(cls.testdir)[0]
        os.chdir(cls.testdir)
        certname = 'testcert.pem'
        if not os.access(certname, os.R_OK):
            create_ssl_certificate(certname)
        cls.certname = certname

    def setUp(self):
        self._tmpindex = 1
        self.__tmpdir = tempfile.mkdtemp('bluepass-test')
        self.__tmpinode = os.stat(self.__tmpdir).st_ino

    def tearDown(self):
        # Some paranoia checks to make me feel better before calling
        # shutil.rmtree()..
        assert '/..' not in self.__tmpdir and '\\..' not in self.__tmpdir
        assert os.stat(self.__tmpdir).st_ino == self.__tmpinode
        try:
            shutil.rmtree(self.__tmpdir)
        except OSError:
            # On Windows a WindowsError is raised when files are
            # still open (WindowsError inherits from OSError).
            pass
        self.__tmpdir = None
        self.__tmpinode = None

    @property
    def tempdir(self):
        return self.__tmpdir

    def tempname(self, name=None):
        if name is None:
            name = 'tmpfile-{0}'.format(self._tmpindex)
            self._tmpindex += 1
        return os.path.join(self.__tmpdir, name)

    def pipename(self, name=None, abstract=False):
        if name is None:
            name = 'tmppipe-{0}'.format(self._tmpindex)
            self._tmpindex += 1
        if sys.platform.startswith('win'):
            return r'\\.\pipe\{0}-{1}'.format(name, os.getpid())
        else:
            prefix = '\x00' if sys.platform.startswith('linux') and abstract else ''
            return prefix + self.tempname(name)

    def get_ssl_context(self):
        context = create_ssl_context(certfile=self.certname, keyfile=self.certname)
        if hasattr(context, 'check_hostname'):
            context.check_hostname = None  # Python 3.4+
        context.verify_mode = ssl.CERT_NONE
        return context

    def assertRaises(self, exc, func, *args, **kwargs):
        # Like unittest.assertRaises, but returns the exception.
        try:
            func(*args, **kwargs)
        except exc as e:
            exc = e
        except Exception as e:
            self.fail('Wrong exception raised: {0!s}'.format(e))
        else:
            self.fail('Exception not raised: {0!s}'.format(exc))
        return exc


class UnitTest(TestCase):
    """Base class for unit tests."""


class PerformanceTest(TestCase):
    """Base class for performance tests."""

    results_name = 'performance.txt'
    test_prefix = 'perf'

    def add_result(self, result, params={}, name=None):
        """Add a performance test result."""
        if name is None:
            frame = sys._getframe(1)
            clsname = frame.f_locals.get('self', '').__class__.__name__
            methname = frame.f_code.co_name
            names = split_cap_words(clsname)
            name = '{0}_{1}'.format(''.join(names[1:]), methname[len(self.test_prefix)+1:]).lower()
        if params is not None:
            params = ','.join(['{0}={1}'.format(k, params[k]) for k in params])
        with open(self.results_name, 'a') as fout:
            fout.write('{0:<32s} {1:<16.2f} {2:s}\n'.format(name, result, params))

    @classmethod
    def setup_loader(cls):
        unittest.TestLoader.testMethodPrefix = cls.test_prefix

    @classmethod
    def start_new_results(cls):
        try:
            os.unlink(cls.results_name)
        except OSError:
            pass


class MemoryTest(PerformanceTest):
    """Special case of a performance test that writes to memory.txt."""

    results_name = 'memory.txt'
    test_prefix = 'mem'
