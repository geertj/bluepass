#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import ssl
from bluepass.ext import _sslex


class SSLSocket(ssl.SSLSocket):
    """An SSLSocket that backports a few features from Python 3.x that we
    depend on:
    
     * Setting the ciphers (missing on 2.6 only).
     * Retrieving the channel bindings.
     * Setting the Diffie-Hellman group parameters.

    This whole thing is a horrible hack. Luckly we don't need it on Python 3.
    """

    def __init__(self, *args, **kwargs):
        """Constructor."""
        self._sslex_ciphers = kwargs.pop('ciphers', None)
        self._sslex_dh_params = kwargs.pop('dh_params', None)
        # Below an even more disgusting hack.. Python's _ssl.sslwrap() requires
        # keyfile and certfile to be set for server sockets. However in case we
        # use anonymous Diffie-Hellman, we don't need these. The "solution" is
        # to force the socket to be a client socket for the purpose of the
        # constructor, and then later patch it to be a server socket
        # (_sslex._set_accept_state()). Fortunately this is solved in Python 3.
        self._sslex_server_side = kwargs.pop('server_side', False)
        super(SSLSocket, self).__init__(*args, **kwargs)

    def do_handshake(self):
        # Our low-level hacks work on _sslobj which is available only when
        # connected. So implement our hacks in do_handshake().
        if self._sslex_ciphers:
            _sslex.set_ciphers(self._sslobj, self._sslex_ciphers)
            self._sslex_ciphers = None
        if self._sslex_dh_params:
            _sslex.load_dh_params(self._sslobj, self._sslex_dh_params)
            self._sslex_dh_params = None
        # Now make it a server socket again if we need to..
        if self._sslex_server_side:
            _sslex._set_accept_state(self._sslobj)
            self._sslex_server_side = None
        super(SSLSocket, self).do_handshake()

    def get_channel_binding(self, typ='tls-unique'):
        """Return the channel binding for this SSL socket."""
        if typ != 'tls-unique':
            raise ValueError('Unsupported channel binding: %s' % typ)
        if self._sslobj is None:
            return
        return _sslex.get_channel_binding(self._sslobj)


def patch_ssl_wrap_socket():
    """Monkey patch ssl.wrap_socket to use our extended SSL socket."""
    import ssl
    def wrap_socket(sock, **kwargs):
        return SSLSocket(sock, **kwargs)
    ssl.wrap_socket = wrap_socket
