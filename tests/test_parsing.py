#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import re

from tests.support import *
from bluepass.parsing import *


class TestTokenize(UnitTest):

    def test_whitespace(self):
        seq = '   +  -- +'
        ws = ' +-'
        tokens = tokenize(seq, ws=ws)
        self.assertEqual(list(tokens), [])

    def test_literal(self):
        seq = '++--]][['
        lit = '+-[]'
        tokens = tokenize(seq, literals=lit)
        self.assertEqual(list(tokens), list(zip(seq, seq)))

    def test_regex(self):
        seq = 'foo qux'
        regexes = [
                ('fb', re.compile('(foo|bar)')),
                ('bq', re.compile('(baz|qux)'))]
        tokens = tokenize(seq, regexes=regexes)
        self.assertEqual(list(tokens), [('fb', 'foo'), ('bq', 'qux')])

    def test_regex_order(self):
        seq = 'foo bar'
        regexes = [
                ('fbr', re.compile('(foo|bar)')),
                ('fbz', re.compile('(bar|baz)'))]
        tokens = tokenize(seq, regexes=regexes)
        self.assertEqual(list(tokens), [('fbr', 'foo'), ('fbr', 'bar')])

    def test_incomplete_regex(self):
        seq = 'foo'
        regexes = [('fb', re.compile('foobar'))]
        tokens = tokenize(seq, regexes=regexes)
        self.assertRaises(ValueError, list, tokens)


class TestLookahead(UnitTest):

    def test_lookahead(self):
        seq = 'foo bar baz'
        regexes = [('id', re.compile('[a-z]+'))]
        tokens = tokenize(seq, regexes=regexes)
        la = lookahead(tokens, 2)
        self.assertEqual(la[:-1], [('id', 'foo'), ('id', 'bar')])
        la = lookahead(tokens, 2)
        self.assertEqual(la[:-1], [('id', 'baz'), ('EOF', '')])

    def test_shift(self):
        seq = 'foo bar baz'
        regexes = [('id', re.compile('[a-z]+'))]
        tokens = tokenize(seq, regexes=regexes)
        la = lookahead(tokens, 1)
        self.assertEqual(shift(la), ('id', 'foo'))
        self.assertEqual(shift(la), ('id', 'bar'))
        self.assertEqual(shift(la), ('id', 'baz'))
        self.assertEqual(shift(la), ('EOF', ''))


class TestCompile(UnitTest):

    def test_basic(self):
        ctx = newctx()
        func = newfunc(ctx, '()')
        emit(func, 'return "foo"')
        funcs = evalctx(ctx)
        self.assertEqual(funcs[func.name](), 'foo')

    def test_args(self):
        ctx = newctx()
        func = newfunc(ctx, '(a, b="bar")')
        emit(func, 'return a,b')
        funcs = evalctx(ctx)
        self.assertEqual(funcs[func.name]('foo', 'bar'), ('foo', 'bar'))

    def test_nested(self):
        ctx = newctx()
        func1 = newfunc(ctx, '()')
        emit(func1, 'return "foo"')
        func2 = newfunc(ctx, '()')
        emit(func2, 'return {0}()', func1.name)
        funcs = evalctx(ctx)
        self.assertEqual(funcs[func2.name](), 'foo')

    def test_globals(self):
        def func():
            return "foo"
        globs = {'func': func}
        ctx = newctx(globs)
        func = newfunc(ctx, '()')
        emit(func, 'return func()')
        funcs = evalctx(ctx)
        self.assertEqual(funcs[func.name](), 'foo')


if __name__ == '__main__':
    unittest.main()
