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

if sys.version_info[:2] >= (2,7):
    import unittest
else:
    import unittest2 as unittest

SkipTest = unittest.SkipTest

__all__ = ['UnitTest', 'PerformanceTest', 'SkipTest', 'unittest', 'unix_only']


def setup_logging():
    """Configure a logger to output to stdout."""
    logger = logging.getLogger()
    if logger.handlers:
        return
    logger.setLevel(logging.DEBUG if '-v' in sys.argv else logging.INFO)
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


class BaseTest(unittest.TestCase):
    """Base class for test suites."""

    @classmethod
    def setUpClass(cls):
        cls.__tmpdir = tempfile.mkdtemp('bluepass-test')
        cls.__tmpinode = os.stat(cls.__tmpdir).st_ino
        cls._tmpindex = 1
        setup_logging()
        testdir = os.path.abspath(os.path.split(__file__)[0])
        os.chdir(testdir)
        if not os.access('testcert.pem', os.R_OK):
            create_ssl_certificate('testcert.pem')
        cls.certname = 'testcert.pem'

    @classmethod
    def tearDownClass(cls):
        # Some paranoia checks to make me feel better before calling
        # shutil.rmtree()..
        assert '/..' not in cls.__tmpdir and '\\..' not in cls.__tmpdir
        assert os.stat(cls.__tmpdir).st_ino == cls.__tmpinode
        try:
            shutil.rmtree(cls.__tmpdir)
        except OSError:
            # On Windows a WindowsError is raised when files are
            # still open (WindowsError inherits from OSError).
            pass
        cls.__tmpdir = None
        cls.__tmpinode = None

    @property
    def tempdir(self):
        return self.__tmpdir

    @classmethod
    def tempname(cls, name=None):
        if name is None:
            name = 'tmpfile-{0}'.format(cls._tmpindex)
            cls._tmpindex += 1
        return os.path.join(cls.__tmpdir, name)

    @classmethod
    def pipename(cls, name):
        if sys.platform.startswith('win'):
            return r'\\.\pipe\{0}-{1}'.format(name, os.getpid())
        else:
            return cls.tempname(name)

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


class UnitTest(BaseTest):
    """Base class for unit tests."""


class PerformanceTest(BaseTest):
    """Base class for performance tests."""

    def add_result(self, result, params={}, name=None):
        """Add a performance test result."""
        if name is None:
            frame = sys._getframe(1)
            clsname = frame.f_locals.get('self', '').__class__.__name__
            methname = frame.f_code.co_name
            name = '{0}_{1}'.format(clsname[4:], methname[5:]).lower()
        if params is not None:
            params = ','.join(['{0}={1}'.format(k, params[k]) for k in params])
        with open('performance.txt', 'a') as fout:
            fout.write('{0:<32s} {1:<16.2f} {2:s}\n'.format(name, result, params))
