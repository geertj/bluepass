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

        /* crypto_sign */

        static char *const crypto_sign_PRIMITIVE;
        static char *const crypto_sign_ed25519_IMPLEMENTATION;
        static char *const crypto_sign_ed25519_tweet_VERSION;

        static int const crypto_sign_ed25519_tweet_BYTES;
        static int const crypto_sign_ed25519_tweet_PUBLICKEYBYTES;
        static int const crypto_sign_ed25519_tweet_SECRETKEYBYTES;

        int crypto_sign_ed25519_tweet(unsigned char *, unsigned long long *,
                const unsigned char *, unsigned long long, const unsigned char *);
        int crypto_sign_ed25519_tweet_open(unsigned char *, unsigned long long *,
                const unsigned char *, unsigned long long, const unsigned char *);
        int crypto_sign_ed25519_tweet_keypair(unsigned char *, unsigned char *);

        /* crypto_stream */

        static char *const crypto_stream_PRIMITIVE;
        static char *const crypto_stream_xsalsa20_IMPLEMENTATION;
        static char *const crypto_stream_xsalsa20_tweet_VERSION;

        static int const crypto_stream_xsalsa20_tweet_KEYBYTES;
        static int const crypto_stream_xsalsa20_tweet_NONCEBYTES;

        int crypto_stream_xsalsa20_tweet(unsigned char *, unsigned long long,
                const unsigned char *, const unsigned char *);
        int crypto_stream_xsalsa20_tweet_xor(unsigned char *, const unsigned char *,
                unsigned long long, const unsigned char *, const unsigned char *);

        /* crypto_scalarmult */

        static char *const crypto_scalarmult_PRIMITIVE;
        static char *const crypto_scalarmult_curve25519_IMPLEMENTATION;
        static char *const crypto_scalarmult_curve25519_tweet_VERSION;

        static int const crypto_scalarmult_curve25519_tweet_BYTES;
        static int const crypto_scalarmult_curve25519_tweet_SCALARBYTES;

        int crypto_scalarmult_curve25519_tweet(unsigned char *, const unsigned char *,
                const unsigned char *);
        int crypto_scalarmult_curve25519_tweet_base(unsigned char *, const unsigned char *);

        /* crypto_onetimeauth */

        static char *const crypto_onetimeauth_PRIMITIVE;
        static char *const crypto_onetimeauth_poly1305_IMPLEMENTATION;
        static char *const crypto_onetimeauth_poly1305_tweet_VERSION;

        static int const crypto_onetimeauth_poly1305_tweet_BYTES;
        static int const crypto_onetimeauth_poly1305_tweet_KEYBYTES;

        int crypto_onetimeauth_poly1305_tweet(unsigned char *, const unsigned char *,
                unsigned long long, const unsigned char *);
        int crypto_onetimeauth_poly1305_tweet_verify(const unsigned char *,
                const unsigned char *, unsigned long long, const unsigned char *);

        /* crypto_hash */

        static char *const crypto_hash_PRIMITIVE;
        static char *const crypto_hash_sha512_IMPLEMENTATION;
        static char *const crypto_hash_sha512_tweet_VERSION;

        static int const crypto_hash_sha512_tweet_BYTES;

        int crypto_hash_sha512_tweet(unsigned char *, const unsigned char *, unsigned long long);

        /* crypto_xor */

        int crypto_xor(unsigned char *, unsigned char *, unsigned long long, unsigned char *);

        """)

parent, _ = os.path.split(os.path.abspath(__file__))
topdir, _ = os.path.split(parent)

lib = ffi.verify("""
        #include "src/tweetnacl.c"
        #include "src/randombytes.c"
        #include "src/xor.c"
        """, modulename='_nacl_ffi', ext_package='bluepass', include_dirs=[topdir])
