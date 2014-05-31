#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import sys
import textwrap
from cffi import FFI

__all__ = []


# We put all platform dependent FFI functions in a single module. This makes
# the setup script simpler because we don't have any conditional compilation.

cdefs = ''
sources = ''

HAVE_PRCTL = sys.platform in ('linux', 'linux2', 'linux3')
HAVE_MLOCKALL = sys.platform in ('linux', 'linux2', 'linux3')

if HAVE_PRCTL:
    cdefs += textwrap.dedent("""\
        #define PR_SET_DUMPABLE ...

        int prctl(int option, unsigned long arg2, unsigned long arg3,
                  unsigned long arg4, unsigned long arg5);
        """)
    sources += textwrap.dedent("""\
        #include <sys/prctl.h>
        """)

if HAVE_MLOCKALL:
    cdefs += textwrap.dedent("""\
        #define MCL_CURRENT ...
        #define MCL_FUTURE ...

        int mlockall(int flags);
        """)
    sources += textwrap.dedent("""\
        #include <sys/mman.h>
        """)

ffi = FFI()
ffi.cdef(cdefs)
lib = ffi.verify(sources, modulename='_platform_ffi', ext_package='bluepass')
