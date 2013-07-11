#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from ..unit import UnitTest, assert_raises
from bluepass.util.json import *


class TestJSON(object):

    def test_unpack_simple(self):
        values = unpack(True, 'b')
        assert values == (True,)
        values = unpack(10, 'i')
        assert values == (10,)
        values = unpack('test', 's')
        assert values == ('test',)
        values = unpack(1.618, 'f')
        assert values == (1.618,)
        values = unpack({'foo':'bar'}, 'o')
        assert values == ({'foo':'bar'},)

    def test_unsigned_int(self):
        values = unpack(0, 'u')
        assert values == (0,)
        values = unpack(1, 'u')
        assert values == (1,)
        assert_raises(UnpackError, unpack, -1, 'u')

    def test_unpack_object(self):
        doc = {'foo': 'bar', 'baz': 'qux'}
        values = unpack(doc, '{s:s,s:s}', ('foo', 'baz'))
        assert values == ('bar', 'qux')

    def test_unpack_nested_object(self):
        doc = {'foo': {'bar': 'baz'}}
        values = unpack(doc, '{s:{s:s}}', ('foo', 'bar'))
        assert values == ('baz',)

    def test_unpack_critical_object(self):
        doc = {'foo': 'bar', 'baz': 'qux'}
        values = unpack(doc, '{s:s,s:s!}', ('foo', 'baz'))
        assert values == ('bar', 'qux')
        assert_raises(UnpackError, unpack, doc, '{s:s!}', ('foo',))
        values = unpack(doc, '{s:s*}', ('foo',))
        assert values == ('bar',)
        values = unpack(doc, '{s:s}', ('foo',))
        assert values == ('bar',)

    def test_unpack_object_with_optional_keys(self):
        doc = {'foo': 'bar'}
        values = unpack(doc, '{s:s,s?:s}', ('foo', 'baz'))
        assert values == ('bar', None)

    def test_unpack_list(self):
        doc = ['foo', 'bar']
        values = unpack(doc, '[ss]')
        assert values == ('foo', 'bar')

    def test_unpack_nested_list(self):
        doc = ['foo', ['bar', 'baz']]
        values = unpack(doc, '[s[ss]]')
        assert values == ('foo', 'bar', 'baz')

    def test_unpack_critical_list(self):
        doc = ['foo', 'bar']
        values = unpack(doc, '[ss!]')
        assert values == ('foo', 'bar')
        assert_raises(UnpackError, unpack, doc, '[s!]')
        values = unpack(doc, '[s*]')
        assert values == ('foo',)
        values = unpack(doc, '[s]')
        assert values == ('foo',)
