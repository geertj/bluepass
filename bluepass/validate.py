#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import re
import base64
import binascii
import six

from collections import namedtuple
from .parsing import *

__all__ = ['compile', 'match', 'validate']


# This module implements a domain specific language for validating nested data
# structures.

def format_path(p):
    if p:
        return '{0}: '.format('/'.join(p))
    else:
        return ''

def add_error(e, p, msg, *args):
    if args:
        msg = msg.format(*args)
    e.append('{0}{1}'.format(format_path(p), msg))


def as_int(val, p, e=None):
    if not isinstance(val, int):
        return add_error(e, p, 'expecting int, got {0.__name__!r}', type(val))
    return val

def as_float(val, p, e=None):
    if isinstance(val, int):
        val = float(val)  # In JSON an int is actually a float
    if not isinstance(val, float):
        return add_error(e, p, 'expecting float, got {0.__name__!r}', type(val))
    return val

def as_bool(val, p, e=None):
    if not isinstance(val, bool):
        return add_error(e, p, 'expecting bool, got {0.__name__!r}', type(val))
    return val

def as_str(val, p, e=None):
    if not isinstance(val, six.string_types):
        return add_error(e, p, 'expecting str, got {0.__name__!r}', type(val))
    return val

_re_uuid = re.compile('^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-'
                      '[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)

def as_uuid(val, p, e=None):
    if not isinstance(val, six.string_types):
        return add_error(e, p, 'expecting str, got {0.__name__!r}', type(val))
    if not _re_uuid.match(val):
        return add_error(e, p, 'illegal uuid: {0}', val)
    return val

def as_base64(val, p, e=None):
    if not isinstance(val, six.string_types):
        return add_error(e, p, 'expecting str, got {0.__name__!r}', type(val))
    try:
        val = base64.b64decode(val)
    except binascii.Error:
        return add_error(e, p, 'illegal base64: {0}', val)
    return val


types = {
    'int': as_int, 'float': as_float, 'bool': as_bool,
    'str': as_str, 'b64': as_base64, 'uuid': as_uuid
}

# A simple recursive descent parser for our validation DSL.
#
# Grammar in EBNF format (grammar is LL(1)):
#
#  top = value
#  value = ["*"], (dict | list | type)
#  dict = "{", { name, ":",  value }, [ELL], "}"
#  list = "[", { value }, [ELL], "]"
#  type = ID, [ or_cond, { "|", or_cond } ]
#  or_cond = { ["@"] CMP literal }
#  literal = NUM | STR
#  name = ID

ws = ' \n\t,'
literals = '{}[]:*@|'
regexes = [('ID', re.compile('[a-zA-Z_][a-zA-Z0-9_]*')),
           ('CMP', re.compile('<(?!=)|<=|>(?!=)|>=|=')),
           ('NUM', re.compile('[0-9]+')),
           ('STR', re.compile('"[^"]*"')),
           ('ELL', re.compile('\.\.\.'))]

Object = namedtuple('Object', ('keys', 'strict', 'opt'))
Key = namedtuple('Key', ('name', 'value'))
Array = namedtuple('Array', ('elems', 'strict', 'opt'))
Type = namedtuple('Type', ('name', 'conds', 'opt'))
Cond = namedtuple('Cond', ('func', 'comp', 'ref'))


def parse(tokens):
    """Parse an validation string *s*."""
    la = lookahead(tokens, 1)
    node = parse_value(la)
    if la[0][0] != 'EOF':
        raise ValueError('additional input present')
    return node

def parse_value(la):
    opt = bool(accept(la, '*'))
    if la[0][0] == '{':
        ret = parse_dict(la, opt)
    elif la[0][0] == '[':
        ret = parse_list(la, opt)
    else:
        ret = parse_type(la, opt)
    return ret

def parse_dict(la, opt):
    expect(la, '{')
    keys = []
    strict = True
    while True:
        tok = accept(la, 'ELL', '}')
        if tok == '...':
            strict = False
            tok = expect(la, '}')
            break
        elif tok == '}':
            break
        name = expect(la, 'ID')
        expect(la, ':')
        value = parse_value(la)
        keys.append(Key(name, value))
    return Object(keys, strict, opt)

def parse_list(la, opt):
    expect(la, '[')
    elems = []
    strict = True
    while True:
        tok = accept(la, 'ELL', ']')
        if tok == '...':
            strict = False
            tok = expect(la, ']')
            break
        elif tok == ']':
            break
        value = parse_value(la)
        elems.append(value)
    return Array(elems, strict, opt)

def parse_type(la, opt):
    name = expect(la, 'ID')
    if name not in types:
        raise ValueError('unknown type: {0}'.format(name))
    or_conds = [[]]
    while True:
        tok = accept(la, '@', 'CMP')
        if tok is None:
            break
        if tok == '@':
            func = 'len'
            comp = expect(la, 'CMP')
        else:
            func = ''
            comp = tok
        ref = expect(la, 'NUM', 'STR')
        or_conds[-1].append(Cond(func, comp, ref))
        if accept(la, '|'):
            or_conds.append([])
    return Type(name, or_conds, opt)


def compile(s):
    tokens = tokenize(s, literals, regexes, ws)
    ast = parse(tokens)
    globs = {}
    for name,func in types.items():
        globs['as_{0}'.format(name)] = func
    globs['add_error'] = add_error
    globs['format_path'] = format_path
    ctx = newctx(globs)
    func = compile_value(ctx, ast)
    locs = evalctx(ctx)
    return Validator(locs[func])

def compile_value(ctx, node):
    if isinstance(node, Object):
        func = compile_dict(ctx, node)
    elif isinstance(node, Array):
        func = compile_list(ctx, node)
    elif isinstance(node, Type):
        func = compile_type(ctx, node)
    return func

def compile_dict(ctx, node):
    func = newfunc(ctx, '(x, p, e, a)')
    emit(func, 'if x is None:')
    if not node.opt:
        emit(func, '  add_error(e, p, "missing dict")')
    emit(func, '  return {}', node.opt)
    emit(func, 'if not isinstance(x, dict):')
    emit(func, '  add_error(e, p, "expecting dict, got {0.__name__!r}", type(x))')
    emit(func, '  return False')
    if node.strict:
        names = set((key.name for key in node.keys))
        emit(func, 'ex = set(x) - {0!s}', names)
        emit(func, 'if ex:')
        emit(func, '  add_error(e, p, "extra keys: {0}", ",".join(ex))')
        emit(func, '  return False')
    emit(func, 'p.append(None)')
    for key in node.keys:
        emit(func, 'v = x.get("{0}")', key.name)
        emit(func, 'p[-1] = "{0}"', key.name)
        emit(func, 'if not {0}(v,p,e,a) and not a:', compile_value(ctx, key.value))
        emit(func, '  return False')
    emit(func, 'p.pop()')
    emit(func, 'return len(e) == 0')
    return func.name

def compile_list(ctx, node):
    func = newfunc(ctx, '(x, p, e, a)')
    emit(func, 'if x is None:')
    if not node.opt:
        emit(func, '  add_error(e, p, "missing list")')
    emit(func, '  return {}', node.opt)
    emit(func, 'if not isinstance(x, list):')
    emit(func, '  add_error(e, p, "expecting list, got {0.__name__!r}", type(x))')
    emit(func, '  return False')
    if node.strict:
        emit(func, 'ex = len(x) - {0}', len(node.elems))
        emit(func, 'if ex > 0:')
        emit(func, '  add_error(e, p, "{0} extra elements".format(ex))')
        emit(func, '  return False')
    pos = 0
    emit(func, 'p.append(None)')
    for elem in node.elems:
        emit(func, 'v = x[{0}] if {0} < len(x) else None', pos)
        emit(func, 'p[-1] = "[{0}]"', pos)
        emit(func, 'if not {0}(v,p,e,a) and not a:', compile_value(ctx, elem))
        emit(func, '  return False')
        pos += 1
    emit(func, 'p.pop()')
    emit(func, 'return len(e) == 0')
    return func.name

def compile_type(ctx, node):
    func = newfunc(ctx, '(x, p, e, a)')
    emit(func, 'if x is None:')
    if not node.opt:
        emit(func, '  add_error(e, p, "missing value")')
    emit(func, '  return {}', node.opt)
    emit(func, 'y = as_{0}(x,p,e)', node.name)
    emit(func, 'if y is None: return False')
    or_terms = []
    for and_conds in node.conds:
        and_terms = []
        for cond in and_conds:
            value = '{0}(y)'.format(cond.func) if cond.func else 'y'
            comp = cond.comp if cond.comp != '=' else '=='
            and_terms.append('({0} {1} {2})'.format(value, comp, cond.ref))
        if and_terms:
            or_terms.append(' and '.join(and_terms))
    if or_terms:
        emit(func, 'if {0}: return True', ' or '.join(or_terms))
        emit(func, 'add_error(e, p, "condition failed")')
        emit(func, 'return False')
    else:
        emit(func, 'return True')
    return func.name


class Result(object):
    """A validation result."""
    
    def __init__(self, match, errors):
        self._match = match
        self._errors = errors

    @property
    def match(self):
        """Whether there was a match."""
        return self._match

    def __bool__(self):
        return self._match

    __nonzero__ = __bool__

    @property
    def error(self):
        """The first error, if any."""
        return self._errors[0] if self._errors else None

    @property
    def errors(self):
        """Return a list of all errors."""
        return self._errors


class ValidationError(Exception):
    """Validation error."""


class Validator(object):
    """Validator object.
    
    Instances of this object are returned by :func:`compile`.
    """

    def __init__(self, vfunc):
        self._vfunc = vfunc

    def match(self, obj):
        """Match the compiled validation expression against the object *obj*.

        Returns a boolean: True if the object matches, False otherwise.
        """
        return self._vfunc(obj, [], [], False)

    def validate(self, obj, all_errors=False):
        """Match the compiled validation expression against the object *obj*.

        If *all_errors* is nonzero, then validation of dicts and lists
        continues after an element fails.

        Returns a :class:`Result` instance.
        """
        errors = []
        return Result(self._vfunc(obj, [], errors, all_errors), errors)

    def validate_raise(self, obj):
        vres = self.validate(obj)
        if not vres:
            raise ValidationError(vres.errors[0])


def validate(obj, s, all_errors=False):
    va = compile(s)
    return va.validate(obj, all_errors)

def match(obj, s):
    va = compile(s)
    return va.match(obj)
