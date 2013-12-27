#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import base64
import binascii
from gruvi import compat

Error = binascii.Error


# Types are as follows:
#
# Encode: bytes -> str
# Decode: str -> bytes
#
# Note this is different from the stdlib where base64 always works on bytes,
# and returns bytes. The types below make more sense to us because we always
# store the result of a base64 encoding in a dict that will be converted to
# JSON, which is unicode based.

def encode(b):
    """Encode a string into base-64 encoding."""
    if not isinstance(b, compat.binary_type):
        raise TypeError('expecting bytes')
    return base64.b64encode(b).decode('ascii')

def decode(s):
    """Decode a base-64 encoded string."""
    if not isinstance(s, compat.string_types):
        raise TypeError('expecting string')
    return base64.b64decode(s)

def check(s):
    """Check that `s' is a properly encoded base64 string."""
    if not isinstance(s, compat.string_types):
        raise TypeError('expecting string')
    try:
        base64.b64decode(s, validate=True)
    except binascii.Error:
        return False
    return True

def try_decode(s):
    """Decode a base64 string and return None if there was an error."""
    try:
        return decode(s)
    except binascii.Error:
        pass
