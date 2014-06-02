#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os.path
from cffi import FFI

__all__ = []


ffi = FFI()
ffi.cdef("""
        int crypto_scrypt(const uint8_t *, size_t, const uint8_t *, size_t,
                          uint64_t, uint32_t, uint32_t, uint8_t *, size_t);
        """)

parent, _ = os.path.split(os.path.abspath(__file__))
topdir, _ = os.path.split(parent)

lib = ffi.verify("""
        #include "src/crypto_scrypt-ref.c"
        #include "src/sha256.c"
        """, modulename='_scrypt_ffi', ext_package='bluepass', include_dirs=[topdir])
