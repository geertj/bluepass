#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import binascii

Error = binascii.Error


def encode(s):
    """Encode a string into base-64 encoding."""
    return binascii.b2a_base64(s).rstrip()

def decode(s):
    """Decode a base-64 encoded string."""
    return binascii.a2b_base64(s)

def check(s):
    """Check that `s' is a properly encoded base64 string."""
    try:
        binascii.b2a_base64(s)
    except binascii.Error:
        return False
    return True

def try_decode(s):
    """Decode a base64 string and return None if there was an error."""
    try:
        return binascii.a2b_base64(s)
    except binascii.Error:
        pass
