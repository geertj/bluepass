#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import sys

if sys.version_info[:2] < (3,3):
    sys.stderr.write('This driver requires Python >= 3.3\n')
    sys.stderr.write('Please use "nosetests" instead.\n')
    sys.exit(1)

from unittest import TestLoader, TextTestRunner

testdir = os.path.split(os.path.abspath(__file__))[0]
os.chdir(testdir)

loader = TestLoader()
tests = loader.discover('.', 'test_*.py')

runner = TextTestRunner(verbosity=1, buffer=True)
runner.run(tests)
