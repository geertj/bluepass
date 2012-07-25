#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

from __future__ import absolute_import

from json import *
import itertools


def dumps_c14n(obj):
    """Serialize an object as canonicalized JSON."""
    return dumps(obj, ensure_ascii=True, sort_keys=True,
                indent=None, separators=(',',':'))

def try_loads(s, cls=None):
    """Load the JSON object in `s` or return None in case there is an error."""
    try:
        obj = loads(s)
    except Exception:
        return
    if cls is not None and not isinstance(obj, cls):
        return
    return obj


class UnpackError(Exception):
    """Validation error."""


def unpack(obj, fmt, names=()):
    """Unpack an object `obj` according to the format string `fmt`.  The
    `names` argument specifies the keys of dictionary entries in the format
    string. The return value is a single, flat tuple with all the unpacked
    values. An UnpackError is raised in case the object cannot be unpacked
    with the provided format string."""
    unpacker = Unpacker(fmt)
    return unpacker.unpack(obj, names)


def check_unpack(obj, fmt, *names):
    """Like unpack() but returns True if the object could be unpacked, and
    False otherwise."""
    try:
        unpack(obj, fmt, *names)
    except UnpackError:
        return False
    return True


class Unpacker(object):
    """A parser and validator for our "unpack" string format.

    The EBNF representation of the grammar is:

      top : value
      value : object | array | type
      object : '{' ('s' ['?'] type)* ['!' | '*'] '}'
      array : '[' value* ['!' | '*'] ']'
      type : 'n' | 'b' | 'i' | 'u' | 's' | 'f' | 'o'

    The tokens ':' and ',' are removed from the input stream, so the more
    natural { s:s, s:s } format can be used instead of {ssss}. Boths forms
    are equivalent.

    The format is very similar to the format uses for Jansson's json_unpack()
    function. That format is documented here:

      http://www.digip.org/jansson/doc/2.3/apiref.html
    """

    def __init__(self, format):
        """Create a new unpacker for format string `format`."""
        self.format = format

    def _tokenize(self):
        """INTERNAL: Return a tokenizer for the format string."""
        for ch in self.format:
            if ch not in ' \t:,':
                yield  ch

    def _accept(self, tokens):
        """INTERNAL: return the next token if it is in `tokens`, or None."""
        if self.current is None or self.current not in tokens:
            return ''
        old = self.current
        self.current = self._tokeniter.next()
        return old

    def _expect(self, tokens):
        """INTERNAL: return the next token if it is in `tokens`, or raise an error."""
        if self.current is None or self.current not in tokens:
            raise ValueError('expecting token: %s (got: %s)' % (tokens, self.current))
        old = self.current
        self.current = self._tokeniter.next()
        return old

    def unpack(self, obj, names=()):
        """Unpack an object according to the format string provided in the
        constructor. The `names` argument specifies the names of dictionary
        entries. The return value is a single, flat tuple with all the
        unpackged values."""
        self._tokeniter = itertools.chain(self._tokenize(), (None,))
        self.current = self._tokeniter.next()
        self._nameiter = itertools.chain(names, (None,))
        self.values = []
        names = iter(names)
        self.p_value(obj)
        if self.current is not None:
            raise ValueError('extra input present')
        return tuple(self.values)

    def p_value(self, ctx):
        """value : object | array | type"""
        for production in self.p_object, self.p_array, self.p_type:
            try:
                production(ctx)
            except ValueError:
                pass
            else:
                return
        raise ValueError('expecting list, object or type')

    def p_object(self, ctx):
        """object : '{' ('s' ['?'] type)* ['!' | '*'] '}'"""
        self._expect('{')
        keys = set()
        while True:
            ch = self._accept('*!}')
            if ch:
                if ch == '!':
                    if ctx and set(ctx) > keys:
                        extra = ', '.join(set(ctx) - keys)
                        raise UnpackError('extra keys in input: %s' % extra)
                if ch != '}':
                    self._expect('}')
                break
            self._expect('s')
            opt = self._accept('?')
            name = self._nameiter.next()
            if name is None:
                raise UnpackError('not enough name arguments provided')
            keys.add(name)
            if ctx is None:
                self.p_value(None)
            elif name not in ctx and not opt:
                raise UnpackError('mandatory key not provided: %s' % name)
            else:
                self.p_value(ctx.get(name))

    def p_array(self, ctx):
        """array : '[' value* ['!' | '*'] ']'"""
        self._expect('[')
        i = 0
        while True:
            ch = self._accept('*!]')
            if ch:
                if ch == '!':
                    if ctx and i != len(ctx):
                        raise UnpackError('more items in input list than expected')
                if ch != ']':
                    self._expect(']')
                break
            if ctx is None:
                self.p_value(None)
            elif i >= len(ctx):
                raise UnpackError('mandatory list item not provided')
            else:
                self.p_value(ctx[i])
                i += 1

    def p_type(self, ctx):
        """type : 'n' | 'b' | 'i' | 'u' | 's' | 'f' | 'o'"""
        typ = self._expect('nbiusfo')
        if ctx is None:
            self.values.append(None)
            return
        if typ == 'n' and ctx is not None:
            raise UnpackError('expecting None')
        elif typ == 'b' and not isinstance(ctx, bool):
            raise UnpackError('expecting boolean')
        elif typ == 'i' and not isinstance(ctx, int):
            raise UnpackError('expecting integer')
        elif typ == 'u' and not (isinstance(ctx, int) and ctx >= 0):
            raise UnpackError('expecting unsigned integer')
        elif typ == 's' and not isinstance(ctx, (str, unicode)):
            raise UnpackError('expecting string')
        elif typ == 'f' and not isinstance(ctx, float):
            raise UnpackError('expecting float')
        self.values.append(ctx)
