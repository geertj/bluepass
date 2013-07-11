#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import

import os
from errno import *


def is_wouldblock(e):
    """Return whether the error number `e` corresponds to the EWOULDBLOCK error."""
    return e in (EWOULDBLOCK, EAGAIN)

def errname(errnum):
    """Return a string name for an error `errnum`."""
    return errorcode.get(errnum, str(errnum))

def strerror(errnum):
    """Return a string describing `errnum`."""
    return os.strerror(errnum)
