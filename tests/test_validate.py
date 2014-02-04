#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import six
from tests.support import *

from bluepass import validate as vmod
from bluepass.validate import *


class TestValidate(UnitTest):

    def test_match(self):
        obj = {'foo': 'bar'}
        self.assertTrue(match(obj, '{foo: str}'))
        self.assertFalse(match(obj, '{foo: int}'))
        self.assertFalse(bool(match(obj, '{foo: int}')))

    def test_validate(self):
        vres = validate({'foo': 'bar'}, '{foo: str}')
        self.assertIsInstance(vres, vmod.Result)
        self.assertTrue(bool(vres))
        self.assertTrue(vres.match)
        self.assertIsNone(vres.error)
        self.assertEqual(vres.errors, [])
        vres = validate({'foo': 'bar'}, '{foo: int}')
        self.assertIsInstance(vres, vmod.Result)
        self.assertFalse(bool(vres))
        self.assertFalse(vres.match)
        self.assertIsInstance(vres.error, six.string_types)
        self.assertEqual(len(vres.errors), 1)
    
    def test_compile(self):
        va = compile('{foo: str}')
        obj = {'foo': 'bar'}
        self.assertTrue(va.match(obj))
        vres = va.validate(obj)
        self.assertIsInstance(vres, vmod.Result)
        self.assertTrue(bool(vres))
        obj = {'foo': 10}
        self.assertFalse(va.match(obj))
        vres = va.validate(obj)
        self.assertIsInstance(vres, vmod.Result)
        self.assertFalse(bool(vres))

    def test_all_errors(self):
        obj = {'foo': 10, 'bar': 10}
        fmt = '{foo: str, bar: str}'
        vres = validate(obj, fmt)
        self.assertEqual(len(vres.errors), 1)
        vres = validate(obj, fmt, all_errors=True)
        self.assertEqual(len(vres.errors), 2)

    def test_types(self):
        self.assertTrue(match(10, 'int'))
        self.assertFalse(match('foo', 'int'))
        self.assertTrue(match(10.0, 'float'))
        self.assertFalse(match(10, 'float'))
        self.assertTrue(match(True, 'bool'))
        self.assertTrue(match(False, 'bool'))
        self.assertFalse(match(None, 'bool'))
        self.assertTrue(match('foo', 'str'))
        self.assertFalse(match(10, 'str'))
        self.assertTrue(match('Zm9v', 'b64'))
        self.assertFalse(match('Zm9', 'b64'))
        self.assertTrue(match('00000000-0000-4000-8000-000000000000', 'uuid'))
        self.assertFalse(match('00000000', 'uuid'))
        self.assertTrue(match({'foo': 'bar'}, '{...}'))
        self.assertFalse(match(['foo', 'bar'], '{...}'))
        self.assertTrue(match(['foo', 'bar'], '[...]'))
        self.assertFalse(match({'foo': 'bar'}, '[...]'))
        self.assertTrue(match([10, 'foo'], '[int, str]'))
        self.assertFalse(match([10, 10], '[int, str]'))

    def test_nested(self):
        obj = {'foo': {'bar': 'baz'}}
        fmt = '{foo: {bar: str}}'
        self.assertTrue(match(obj, fmt))
        obj = {'foo': ['bar', 'baz']}
        fmt = '{foo: [str, str]}'
        self.assertTrue(match(obj, fmt))

    def test_strict(self):
        obj = {'foo': 1, 'bar': 2}
        fmt = '{foo: int}'
        self.assertFalse(match(obj, fmt))
        fmt = '{foo: int, ...}'
        self.assertTrue(match(obj, fmt))
        obj = [1, 2]
        fmt = '[int]'
        self.assertFalse(match(obj, fmt))
        fmt = '[int, ...]'
        self.assertTrue(match(obj, fmt))

    def test_optional(self):
        self.assertTrue(match(None, '*int'))
        self.assertFalse(match(None, 'int'))
        vres = validate({}, '{foo: *str}')
        self.assertTrue(match({}, '{foo: *str}'))
        self.assertFalse(match({}, '{foo: str}'))
        self.assertTrue(match([], '[*str]'))
        self.assertFalse(match([], '[str]'))
        self.assertTrue(match(None, '*{foo: str}'))
        self.assertFalse(match(None, '{foo: str}'))
        vres = validate(None, '*[str]')
        self.assertTrue(match(None, '*[str]'))
        self.assertFalse(match(None, '[str]'))

    def test_condition(self):
        self.assertTrue(match(10, 'int>9'))
        self.assertTrue(match(10, 'int>=10'))
        self.assertTrue(match(10, 'int=10'))
        self.assertTrue(match(10, 'int<=10'))
        self.assertTrue(match(10, 'int<11'))
        self.assertFalse(match(10, 'int>11'))
        self.assertFalse(match(10, 'int>=11'))
        self.assertFalse(match(10, 'int=11'))
        self.assertFalse(match(10, 'int<=9'))
        self.assertFalse(match(10, 'int<9'))
        self.assertFalse(match(10, 'int<=9'))
        self.assertTrue(match(10, 'int>9<11'))
        self.assertFalse(match(10, 'int>9>11'))
        self.assertTrue(match(10, 'int>9|>11'))
        self.assertTrue(match('foo', 'str@>2'))
        self.assertTrue(match('foo', 'str@=3'))
        self.assertTrue(match('foo', 'str@<4'))
        self.assertFalse(match('foo', 'str@>3'))
        self.assertFalse(match('foo', 'str@=4'))
        self.assertFalse(match('foo', 'str@<2'))
        self.assertTrue(match(15, 'int>10<20'))
        self.assertFalse(match(15, 'int>10>20'))
        self.assertTrue(match('foo', 'str@>1@<5'))
        self.assertFalse(match('foo', 'str@>1@>5'))


if __name__ == '__main__':
    unittest.main()
