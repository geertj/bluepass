#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import six
import pyuv

from .scrypt_ffi import lib as _lib, ffi as _ffi


class ScryptError(Exception):
    """scrypt error"""


def scrypt(password, salt, N, r, p, l):
    """Generate an encryption key from a password using scrypt().

    The *password* parameter is the password to genate an encryption key from,
    and *salt* is a salt. Both may be bytes objects or strings. If they are
    strings then they are encoded in UTF-8 before passing them to the key
    derivation function.

    The *N*, *r*, *p* are tunable parameters that determine the work factor.
    See the scrypt homepage here: http://www.tarsnap.com/scrypt.html.

    The return value is a bytes object of length *l*.
    """
    if isinstance(password, six.text_type):
        password = password.encode('utf8')
    if isinstance(salt, six.text_type):
        salt = salt.encode('utf8')
    buf = _ffi.new('char[{0}]'.format(l+1))
    ret = _lib.crypto_scrypt(password, len(password), salt, len(salt), N, r, p, buf, l)
    if ret != 0:
        raise ScryptError('crypto_scrypt() returned with status {0!r}'.format(ret))
    return bytes(_ffi.buffer(buf, l))


def scrypt_params():
    """Return suitable parameters for scrypt().

    The return value is a tuple (N, r, p).
    """
    memory = pyuv.util.get_total_memory() // (1024 * 1024)
    cpuspeed = pyuv.util.cpu_info()[0].speed
    arch = os.uname().machine if hasattr(os, 'uname') else None
    # The total memory used is 128*N*r
    if memory > 1000 and cpuspeed > 1000 and arch == 'x86_64':
        # Desktop class machine. Use 16MB of RAM and < 0.3 sec
        N = 2**14
    else:
        # Older or mobile? Use 4 MB of RAM.
        N = 2**12
    r = 8; p = 1
    return N, r, p
