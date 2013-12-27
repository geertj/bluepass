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
import shutil
import tempfile
import unittest

if sys.version_info[:2] >= (2,7):
    import unittest
else:
    import unittest2 as unittest

SkipTest = unittest.SkipTest

__all__ = ['UnitTest', 'SkipTest', 'unittest']


def assert_raises(exc, func, *args):
    """Like nose.tools.assert_raises but returns the exception."""
    try:
        func(*args)
    except Exception as e:
        if isinstance(e, exc):
            return e
        raise
    raise AssertionError('%s not raised' % exc.__name__)


class UnitTest(unittest.TestCase):
    """Base class for unit tests."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.prevdir = os.getcwd()
        os.chdir(cls.tmpdir)
        cls.tmpdirs = []

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.prevdir)
        shutil.rmtree(cls.tmpdir)
        for tmpdir in cls.tmpdirs:
            shutil.rmtree(tmpdir)

    def tempfile(self):
        return tempfile.mkstemp(dir=self.tmpdir)[1]

    def tempdir(self):
        tmpdir = tempfile.mkdtemp()
        self.tmpdirs.append(tmpdir)
        return tmpdir

    def write_file(self, fname, contents):
        fout = file(fname, 'w')
        fout.write(contents)
        fout.close()

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
