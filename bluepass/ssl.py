#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import ssl
import socket

from bluepass.ext import _sslex


class SSLSocket(ssl.SSLSocket):
    """An extended version of SSLSocket.
    
    This backports two features from Python 3.x to 2.x that we depend on:

    * Retrieving the channel bindings (get_channel_bindings()).
    * Setting the Diffie-Hellman group parameters (via the "dhparams"
       and dh_single_use keyword arguments to the constructor).

    This whole thing is a horrible hack. Luckly we don't need it on Python 3.
    """

    def __init__(self, *args, **kwargs):
        """Constructor."""
        # Below an even more disgusting hack.. Python's _ssl.sslwrap() requires
        # keyfile and certfile to be set for server sockets. However in case we
        # use anonymous Diffie-Hellman, we don't need these. The "solution" is
        # to force the socket to be a client socket for the purpose of the
        # constructor, and then later patch it to be a server socket
        # (_sslex._set_accept_state()). Fortunately this is solved in Python
        # 3.x.
        self._sslex_dhparams = kwargs.pop('dhparams', '')
        self._sslex_dh_single_use = kwargs.pop('dh_single_use', False)
        self._sslex_server_side = kwargs.pop('server_side', False)
        self._sslex_ciphers = kwargs.pop('ciphers', None)
        super(SSLSocket, self).__init__(*args, **kwargs)

    def do_handshake(self):
        """Set DH parameters prior to handshake."""
        if self._sslex_dhparams:
            _sslex.set_dh_params(self._sslobj, self._sslex_dhparams,
                                 self._sslex_dh_single_use)
            self._sslex_dhparms = None
        if self._sslex_ciphers:
            _sslex.set_ciphers(self._sslobj, self._sslex_ciphers)
            self._sslex_ciphers = None
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
    from gruvi import compat
    if compat.PY3:
        return
    import ssl
    def wrap_socket(sock, **kwargs):
        return SSLSocket(sock, **kwargs)
    ssl.wrap_socket = wrap_socket
