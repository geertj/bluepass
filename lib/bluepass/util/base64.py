#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

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
