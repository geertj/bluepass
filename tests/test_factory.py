#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from bluepass.factory import *
from unit import *


class Dummy(object):
    pass


class TestFactory(UnitTest):

    def test_factory(self):
        self.assertRaises(RuntimeError, instance, Dummy)
        obj = singleton(Dummy)
        self.assertIs(instance(Dummy), obj)
        self.assertRaises(RuntimeError, singleton, Dummy)
        self.assertIs(instance(Dummy), obj)


if __name__ == '__main__':
    unittest.main()
