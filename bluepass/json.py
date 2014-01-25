#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from json import *


def dumps_c14n(obj):
    """Serialize an object as canonicalized JSON."""
    return dumps(obj, sort_keys=True, indent=None, separators=(',',':'))

def dumps_pretty(obj):
    """Pretty-print a JSON message."""
    return dumps(obj, sort_keys=True, indent=2) + '\n'


def try_loads(s, cls=None):
    """Load the JSON object in `s` or return None in case there is an error."""
    try:
        obj = loads(s)
    except Exception as e:
        return
    if cls is not None and not isinstance(obj, cls):
        return
    return obj
