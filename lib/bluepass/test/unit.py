#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import os
import shutil
import tempfile


def assert_raises(exc, func, *args):
    """Like nose.tools.assert_raises but returns the exception."""
    try:
        func(*args)
    except Exception as e:
        if isinstance(e, exc):
            return e
        raise
    raise AssertionError('%s not raised' % exc.__name__)


class UnitTest(object):
    """Base class for unit tests."""

    @classmethod
    def setup_class(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.prevdir = os.getcwd()
        os.chdir(cls.tmpdir)
        cls.tmpdirs = []

    @classmethod
    def teardown_class(cls):
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
