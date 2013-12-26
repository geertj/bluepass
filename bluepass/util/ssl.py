#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

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
        self.dhparams = kwargs.pop('dhparams', '')
        self.dh_single_use = kwargs.pop('dh_single_use', False)
        self.server_side = kwargs.pop('server_side', False)
        self.ciphers = kwargs.pop('ciphers', None)
        super(SSLSocket, self).__init__(*args, **kwargs)

    def do_handshake(self):
        """Set DH parameters prior to handshake."""
        if self.dhparams:
            _sslex.set_dh_params(self._sslobj, self.dhparams, self.dh_single_use)
        if self.ciphers:
            _sslex.set_ciphers(self._sslobj, self.ciphers)
        # Now make it a server socket again if we need to..
        if self.server_side:
            _sslex._set_accept_state(self._sslobj)
        super(SSLSocket, self).do_handshake()

    def get_channel_binding(self, typ='tls-unique'):
        """Return the channel binding for this SSL socket."""
        if typ != 'tls-unique':
            raise ValueError('Unsupported channel binding: %s' % typ)
        if self._sslobj is None:
            return
        return _sslex.get_channel_binding(self._sslobj)


def patch_gruvi_ssl():
    """Monkey patch gruvi.ssl to use our extended SSL socket."""
    from gruvi import compat
    if compat.PY3:
        return
    import gruvi.ssl
    def wrap_socket(*args, **kwargs):
        return SSLSocket(*args, **kwargs)
    gruvi.ssl.wrap_socket = wrap_socket
