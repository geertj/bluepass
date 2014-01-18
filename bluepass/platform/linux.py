#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from bluepass.errors import *
from .platform_ffi import lib as _lib

__all__ = ['disable_debugging', 'lock_all_memory']


def disable_debugging():
    """Disable debugging.

    Under Linux it's possible to use the ptrace() debugging API to read the
    memory of other processes with the same UID. This function disables that by
    setting the PR_SET_DUMPABLE prctl() flag to 0.
    """
    ret = _lib.prctl(_lib.PR_SET_DUMPABLE, 0, 0, 0, 0)
    if ret != 0:
        raise PlatformError('prctl() returned with error {0}'.format(ret))


def lock_all_memory():
    """Lock all memory.

    This prevents any of our memory from being swapped to disk. Note that this
    call will likely fail if CAP_IPC_LOCK is not available.
    """
    ret = _lib.mlockall(_lib.MCL_CURRENT | _lib.MCL_FUTURE)
    if ret != 0:
        raise PlatformError('mlockall() returned with error {0}'.format(ret))
