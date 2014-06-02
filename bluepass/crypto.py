#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import random
import uuid
import string
import math

from bluepass.nacl import *
from bluepass.scrypt import *


def random_bytes(count):
    """Return *count* random bytes."""
    return os.urandom(count)

def random_int(below):
    """Return a random integer < *below*."""
    return random.randrange(0, below)

def random_uuid():
    """Return a type-4 random UUID."""
    return str(uuid.uuid4())

_cookie_chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
_bits_per_cookie_char = math.log(len(_cookie_chars), 2)

def random_cookie(bits=128):
    """Return a cookie with at least *bits* of entropy."""
    nchars = int(bits/_bits_per_cookie_char + 1)
    return ''.join([random_element(_cookie_chars) for i in range(nchars)])

def random_element(elements):
    """Return a random element from *elements*."""
    return random.choice(elements)


import hashlib
import hmac as hmaclib

def _get_hash(name):
    if not hasattr(hashlib, name):
        raise ValueError('no such hash function: %s' % name)
    return getattr(hashlib, name)

def hmac(key, message, hash='sha256'):
    """Return the HMAC of *message* under *key*."""
    md = _get_hash(hash)
    return hmaclib.new(key, message, md).digest()
