#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import re
import sys
import six

from collections import namedtuple

__all__ = ['tokenize', 'lookahead', 'shift', 'accept', 'expect', 'newctx',
           'newfunc', 'emit', 'evalctx']


def tokenize(s, literals='', regexes=[], ws=' \n\t'):
    """Tokenize a string.
    
    This returns an iterator that yields ``(token, value)`` tuples.

    The *literals* argument is a sequence of 1-character literal tokens whose
    token identifier is also their value.
    
    The *regexes* argument must be a list of ``(id, compiled_regex)`` tuples.
    Each compiled regex is matched to input from the string. The first match
    found is returned. This means that the list must be given in priority
    order. Each regex token must be separated from other regex token on both
    sides by whitespace, a literal token, the beginning or the end of the
    string.

    The optional *ws* argument is a sequence of whitespace characters that are
    ignored.

    The iteration raises a ValueError when token cannot be recognized.
    """
    pos = 0
    while pos < len(s):
        # Skip whitespace
        if s[pos] in ws:
            pos += 1
            continue
        # Try any of the regex tokens
        found_regex = False
        for typ,regex in regexes:
            mobj = regex.match(s, pos)
            if mobj is None:
                continue
            yield (typ, mobj.group(0))
            pos += len(mobj.group(0))
            found_regex = True
            break
        if found_regex:
            continue
        # Lastly try literals
        if s[pos] in literals:
            yield (s[pos], s[pos])
            pos += 1
            continue
        raise ValueError('unrecognized token "{0:.10}.." at posn {1}'.format(s[pos:], pos))


def next_token(tokens):
    """Return the next tuple in *tokens*, or the special 'EOF' token if the end
    of stream has been reached."""
    try:
        return six.next(tokens)
    except StopIteration:
        return ('EOF', '')

def lookahead(tokens, n):
    """Look ahead *n* tokens in the stream *tokens*.

    This returns a list with N+1 elements. The first N elements are tuples read
    from *tokens*, or None if the stream is exhausted. Element N+1 is the
    *tokens* stream itself.
    """
    return [next_token(tokens) for i in range(n)] + [tokens]


def shift(la):
    """Shift a (token, lexeme) tuple from the lookahead list *la*.

    The shifted tuple is returned, and a new tuple is read.
    """
    tup = la.pop(0)
    tokens = la.pop()
    la.append(next_token(tokens))
    la.append(tokens)
    return tup

def accept(la, *tokens):
    """If the next token in the lookahead list *la* is in *tokens*, then return
    the lexeme. Otherwise, return None."""
    if la[0][0] in tokens:
        return shift(la)[1]

def expect(la, *tokens):
    """If the next token in the lookahead list *la* is in *tokens*, then return
    the lexeme. Otherwise, raise a ValueError exception."""
    if la[0][0] in tokens:
        return shift(la)[1]
    tok = '|'.join([tok for tok in tokens])
    raise ValueError('expecting token "{0}", got "{1}"'.format(tok, la[0][0]))


# Code generation

Ctx = namedtuple('Ctx', ('funcs', 'globs'))
Func = namedtuple('Func', ('name', 'lines', 'indent'))

def newctx(globs=None):
    return Ctx([], globs if globs is not None else {})

def newfunc(ctx, sign):
    name = 'func{0}'.format(len(ctx.funcs))
    func = Func(name, ['def {0}{1}:'.format(name, sign)], 2)
    ctx.funcs.append(func)
    return func

def emit(func, line, *args):
    if args:
        line = line.format(*args)
    func.lines.append(func.indent * ' ' + line)

def evalctx(ctx):
    lines = []
    for func in ctx.funcs:
        lines += func.lines
    text = '\n'.join(lines)
    code = compile(text, '<codegen>', 'exec')
    locs = {}
    eval(code, ctx.globs, locs)
    assert len(locs) == len(ctx.funcs)
    ctx.globs.update(locs)  # expose functions to each other
    return locs
