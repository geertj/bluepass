#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

"""
The :mod:`nacl` module provides a Python interface to DJB's NaCl cryptographic
library. In this case, the NaCl implementation is provided by a built-in copy
of TweetNacl. TweetNaCl is a tiny library that implements most of the NaCl API
and that fits in 100 Tweets. Its focus is on auditable security and it is
intended to be embedded into applications rather than used as a shared library.

For extensive documentation on the NaCl cryptographic primitives, see the NaCl
homepage at http://nacl.cr.yp.to/.

NaCl methods and constants are exposed as Python functions and module
attributes respectively. In addition, there are two low-level plumbing
functions:

 * The function :func:`implementation` can be used to look up what
   implementation is available for a certain algorithm class.
 * The function :func:`lookup` resolves and returns a NaCl library constant
   or function.
"""

from __future__ import absolute_import, print_function

import os
import functools
import six
import pyuv

from .nacl_ffi import ffi as _ffi, lib as _lib


class NaclError(Exception):
    """NaCl error.

    This exception is raised whenever a NaCl function returns with an error
    (unless documented otherwise like e.g. with :func:`sign_verify`).
    """


def _newbuf(arg):
    """Create a new CFFI char[] buffer."""
    if not isinstance(arg, (int, bytes)):
        raise TypeError('expecting int or bytes, got {0!r}'.format(type(arg).__name__))
    return _ffi.new('char[]', arg)

def _cd2s(cd):
    """Convert a CFFI cdata object into a string."""
    s = _ffi.string(cd)
    if six.PY3:
        s = s.decode('ascii')
    return s

def _cd2b(cd, l=-1):
    """Convert a CFFI cdata object into a bytes instance."""
    return bytes(_ffi.buffer(cd, l))


def _check_binarg(name, value, sizename=None, impl=None):
    """Check type and optionally size of a binary argument."""
    if isinstance(value, (bytearray, memoryview)):
        value = bytes(value)
    elif not isinstance(value, bytes):
        raise TypeError('{0}: expecting bytes-like instance, got {1!r}'
                        .format(name, type(value).__name__))
    if sizename:
        size = lookup(sizename, impl)
        if len(value) != size:
            raise ValueError('{0}: expecting {1} ({2}) bytes, got {3}'
                             .format(name, sizename, size, len(value)))
    return value


_impl_cache = {}

def implementation(name, impl=None):
    """Lookup and check the implementation for an algorithm class.

    The *name* argument specifies the algorithm class. It must be one of the
    NaCl algorithm classes such as ``'sign'`` or ``'box'``.

    If *impl* is provided, it must be a partial implementation specifier in the
    form "primitive[/implementation]".

    The return value is the full implementation specifier in the form
    "primitive/implementation/version".
    """
    key = name if impl is None else '{0}/{1}'.format(name, impl)
    cached = _impl_cache.get(key)
    if cached:
        return cached
    if not hasattr(_lib, 'crypto_{0}_PRIMITIVE'.format(name)):
        raise ValueError('unknown algorithm class: {0!r}'.format(name))
    if not impl:
        impl = [None, None, None]
    elif isinstance(impl, str):
        impl = impl.split('/')
        if len(impl) > 3:
            raise ValueError('impl: must contain <= 2 components')
        impl += [None] * (3-len(impl))
    else:
        raise TypeError('impl: must be None or str')
    if not impl[0]:
        impl[0] = _cd2s(getattr(_lib, 'crypto_{0}_PRIMITIVE'.format(name)))
    elif not hasattr(_lib, 'crypto_{0}_{1[0]}_IMPLEMENTATION'.format(name, impl)):
         raise ValueError('unknown primitive: {0!r}'.format(impl[0]))
    if impl[1] is None:
        impl[1] = _cd2s(getattr(_lib, 'crypto_{0}_{1[0]}_IMPLEMENTATION'
                                    .format(name, impl))).split('/')[2]
    elif not hasattr(_lib, 'crypto_{0}_{1[0]}_{1[1]}_VERSION'.format(name, impl)):
        raise ValueError('unknown implementation: {0!r}'.format(impl[1]))
    impl[2] = _cd2s(getattr(_lib, 'crypto_{0}_{1[0]}_{1[1]}_VERSION'.format(name, impl)))
    impl = '/'.join(impl)
    _impl_cache[key] = impl
    return impl


_obj_cache = {}

def _func_wrapper(name, func, *args):
    """Wrapper for calling a NaCl function."""
    ret = func(*args)
    if ret != 0:
        raise NaclError('{0}() failed with status {1}'.format(name, ret))

def lookup(name, impl=None):
    """Look up and return a NaCl lookup.

    The lookup named *name* is looked up and returned. The name must be in the
    form "class_lookup", with "class" one of the valid NaCl algorithm classes
    like ``'stream'`` or ``'scalarmult'``, and  "lookup" a constant name or an
    optional function name.

    If *impl* is provided, it must be a valid implementation specifier in the
    form "primitive[/implementation[/version]]". If *impl* is not provided, the
    default implementation for the class is used.

    The return value is an integer or a string if looking up a constant, or a
    callable if looking up a function.
    """
    key = name if impl is None else '{0}/{1}'.format(name, impl)
    cached = _obj_cache.get(key)
    if cached:
        return cached
    names = name.split('_')
    if not 1 <= len(names) <= 2:
        raise ValueError('name: must be in the form "class[_lookup]')
    impl = implementation(names[0], impl).split('/')
    if len(names) == 1:
        sname = 'crypto_{0[0]}_{1[0]}_{1[1]}'.format(names, impl)
    else:
        sname = 'crypto_{0[0]}_{1[0]}_{1[1]}_{0[1]}'.format(names, impl)
    value = getattr(_lib, sname, None)
    if value is None:
        raise ValueError('no such lookup: {0}'.format(name))
    if isinstance(value, _ffi.CData):
        value = _cd2s(value)
    elif callable(value):
        value = functools.partial(_func_wrapper, name, value)
    _obj_cache[key] = value
    return value


randombytes = os.urandom

# crypto_sign: public key signatures

sign_BYTES = lookup('sign_BYTES')
sign_PUBLICKEYBYTES = lookup('sign_PUBLICKEYBYTES')
sign_SECRETKEYBYTES = lookup('sign_SECRETKEYBYTES')


def sign_keypair(impl=None):
    """Create a new keypair for creating signatures.

    The return value is 2-tuple (public, secret), containing the public and
    secret keys as byte objects respectively.
    """
    impl = implementation('sign', impl)
    pk = _newbuf(lookup('sign_PUBLICKEYBYTES', impl))
    sk = _newbuf(lookup('sign_SECRETKEYBYTES', impl))
    lookup('sign_keypair', impl)(pk, sk)
    return (_cd2b(pk), _cd2b(sk))


def sign(msg, sk, impl=None):
    """Sign the message *msg* with secret key *sk*.

    The *msg* and *sk* arguments must be bytes-like objects. The *msg* argument
    may be of arbitrary size. The *sk* object must be the secret key of a
    keypair returned by :func:`sign_keypair`, and must be
    ``sign_SECRETKEYBYTES`` long.

    The return value is the detached signature. This is different from the NaCl
    API where the return value is a signed message containing both the
    clear-text message as well as the signature.
    """
    impl = implementation('sign', impl)
    sk = _check_binarg('sk', sk, 'sign_BYTES', impl)
    slen = lookup('sign_BYTES', impl)
    sm = _newbuf(slen + len(msg))
    smlen = _ffi.new('unsigned long long *')
    lookup('sign', impl)(sm, smlen, msg, len(msg), sk)
    assert smlen[0] == slen + len(msg)
    return _cd2b(sm, slen)


def sign_verify(msg, sig, pk, impl=None):
    """Verify a detached signature *sig* for message *msg* using public key *pk*.

    The *msg*, *sig* and *pk* arguments must be bytes-like objects. The *sig*
    argument must be ``sign_BYTES`` in size. The *pk* argument must be the
    public key of a keypair created by :func:`sign_keypair`, and must be
    ``sign_PUBLICKEYBYTES`` long.

    Return True if the signature is correct, False otherwise.
    """
    impl = implementation('sign', impl)
    msg = _check_binarg('msg', msg)
    sig = _check_binarg('sig', sig, 'sign_BYTES', impl)
    pk = _check_binarg('pk', pk, 'sign_PUBLICKEYBYTES', impl)
    sm = _newbuf(sig + msg)
    smlen = len(msg) + len(sig)
    m = _newbuf(smlen)
    mlen = _ffi.new('unsigned long long *')
    try:
        lookup('sign_open', impl)(m, mlen, sm, smlen, pk)
    except NaclError:
        return False
    return True


# crypto_stream: stream cipher

stream_NONCEBYTES = lookup('stream_NONCEBYTES')
stream_KEYBYTES = lookup('stream_KEYBYTES')


def stream(clen, nonce, key, impl=None):
    """Generate a keystream of *clen* bytes using *nonce* and *key*.

    Both *nonce* and *key* must be bytes-like objects. They must be exactly
    ``stream_NONCEBYTES`` and ``stream_KEYBYTES`` in size, respectively.

    The produced keystream is returned as a bytes instance.
    """
    impl = implementation('stream', impl)
    nonce = _check_binarg('nonce', nonce, 'stream_NONCEBYTES', impl)
    key = _check_binarg('key', key, 'stream_KEYBYTES', impl)
    c = _newbuf(clen)
    lookup('stream', impl)(c, clen, nonce, key)
    return _cd2b(c)


def stream_xor(msg, nonce, key, impl=None):
    """Generate a keystream with :func:`stream` and XOR *msg* to it.

    The encrypted message is returned as a bytes objects.
    """
    impl = implementation('stream', impl)
    msg = _check_binarg('msg', msg)
    nonce = _check_binarg('nonce', nonce, 'stream_NONCEBYTES', impl)
    key = _check_binarg('key', key, 'stream_KEYBYTES', impl)
    m = _newbuf(msg)
    mlen = len(msg)
    c = _newbuf(mlen)
    lookup('stream_xor', impl)(c, m, mlen, nonce, key)
    return _cd2b(c)


# crypto_scalarmult: EC scalar multiplication (ECDH)

scalarmult_BYTES = lookup('scalarmult_BYTES')
scalarmult_SCALARBYTES = lookup('scalarmult_SCALARBYTES')


def scalarmult(n, p, impl=None):
    """Perform a multiplication of the group element *p* by the scalar *n*.

    Both *n* and *p* must be bytes-like objects. They must be exactly
    ``scalarmult_SCALARBYTES`` and ``scalarmult_BYTES`` in size, respectively.

    The return value is a bytes object of size ``scalarmult_BYTES``.
    """
    impl = implementation('scalarmult', impl)
    n = _check_binarg('n', n, 'scalarmult_SCALARBYTES', impl)
    p = _check_binarg('p', p, 'scalarmult_BYTES', impl)
    q = _newbuf(lookup('scalarmult_BYTES', impl))
    lookup('scalarmult', impl)(q, n, p)
    return _cd2b(q)


def scalarmult_base(n, impl=None):
    """Perform a multiplication of the group base element by the scalar *n*.

    The *n* argument must be a bytes-like object of size
    ``scalarmult_SCALARBYTES``.

    The return value is a bytes object of size ``scalarmult_BYTES``.
    """
    impl = implementation('scalarmult', impl)
    n = _check_binarg('n', n, 'scalarmult_SCALARBYTES', impl)
    q = _newbuf(lookup('scalarmult_BYTES', impl))
    lookup('scalarmult_base', impl)(q, n)
    return _cd2b(q)


# crypto_onetimeauth: one time authentication

onetimeauth_BYTES = lookup('onetimeauth_BYTES');
onetimeauth_KEYBYTES = lookup('onetimeauth_KEYBYTES');


def onetimeauth(msg, key, impl=None):
    """Create a one-time autenticator for *msg* under *key*.

    Both *msg* and *key* must be bytes-like objects. The *msg* argument can be
    of arbitrary size, while the *key* argument must be of size
    ``onetimeauth_KEYBYTES``.

    The return value is the authenticator which is a bytes object of size
    ``onetimeauth_BYTES``.
    """
    impl = implementation('onetimeauth', impl)
    msg = _check_binarg('msg', msg)
    key = _check_binarg('key', key, 'onetimeauth_KEYBYTES', impl)
    a = _newbuf(lookup('onetimeauth_BYTES', impl))
    lookup('onetimeauth', impl)(a, msg, len(msg), key)
    return _cd2b(a)


def onetimeauth_verify(auth, msg, key, impl=None):
    """Verify a one-time authenticator *auth* for *key* under *msg*.

    The *auth*, *msg* and *key* arguments must all be bytes-like objects. The
    *auth* argument must be of size, ``onetimeauth_BYTES``, the *msg* argument
    does not have a size limit, and the *key* argument must be of size
    ``onetimeauth_KEYBYTES``.

    The return value is a boolean indicating whether the authenticator is valid.
    """
    impl = implementation('onetimeauth', impl)
    auth = _check_binarg('auth', auth, 'onetimeauth_BYTES', impl)
    msg = _check_binarg('msg', msg)
    key = _check_binarg('key', key, 'onetimeauth_KEYBYTES', impl)
    try:
        lookup('onetimeauth_verify', impl)(auth, msg, len(msg), key)
    except NaclError:
        return False
    return True


# crypto_hash: hashing

def hash(msg, impl=None):
    """Compute a hash for message *msg*.

    The *msg* argument must be a bytes-like object and can be of arbitrary
    size.

    The return value is a bytes instance containing the hash.
    """
    impl = implementation('hash', impl)
    msg = _check_binarg('msg', msg)
    h = _newbuf(lookup('hash_BYTES', impl))
    lookup('hash')(h, msg, len(msg))
    return _cd2b(h)


# crypto_xor: one time pad

def xor(msg, key, impl=None):
    msg = _check_binarg('msg', msg)
    key = _check_binarg('key', key)
    if len(msg) != len(key):
        raise ValueError('message and key must be of equal length')
    c = _newbuf(len(msg))
    _lib.crypto_xor(c, msg, len(msg), key)
    return _cd2b(c)
