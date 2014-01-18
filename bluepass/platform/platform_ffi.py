#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import sys
from cffi import FFI

__all__ = []


# We put all platform dependent FFI functions in a single module. This makes
# the setup script simpler because we don't have any conditional compilation.

cdefs = ''
sources = ''

if sys.platform in ('linux', 'linux2'):
    cdefs += """
        #define PR_SET_DUMPABLE ...

        int prctl(int option, unsigned long arg2, unsigned long arg3,
                  unsigned long arg4, unsigned long arg5);
        """
    sources += """
        #include <sys/prctl.h>
        """

if sys.platform in ('linux', 'linux2'):
    cdefs += """
        #define MCL_CURRENT ...
        #define MCL_FUTURE ...

        int mlockall(int flags);
        """
    sources += """
        #include <sys/mman.h>
        """

ffi = FFI()
ffi.cdef(cdefs)
lib = ffi.verify(sources, modulename='bluepass_platform_cffi')
