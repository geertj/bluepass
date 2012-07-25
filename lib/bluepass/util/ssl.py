#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import httplib
from gevent import socket, ssl
from bluepass.ext import _sslex


class SSLSocket(ssl.SSLSocket):
    """An extended version of SSLSocket.
    
    This backports two features from Python 3.x to 2.x that we depend on:

    * Retrieving the channel bindings (get_channel_bindings()).
    * Setting the Diffie-Hellman group parameters (via the "dhparams"
       and dh_single_use keyword arguments to the constructor).
    """

    def __init__(self, *args, **kwargs):
        """Constructor."""
        # Below we have a horrible hack... Python's _ssl.sslwrap() requires
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


def wrap_socket(*args, **kwargs):
    return SSLSocket(*args, **kwargs)


class HTTPSConnection(httplib.HTTPConnection):
    """HTTPS connection that uses our extended SSLSocket."""

    default_port = httplib.HTTPS_PORT

    def __init__(self, host, port=None, sockinfo=None, **ssl_args):
        httplib.HTTPConnection.__init__(self, host, port)
        self.sockinfo = sockinfo
        self.ssl_args = ssl_args
        self.timeout = socket.getdefaulttimeout()

    def connect(self):
        if self.sockinfo is not None:
            si = self.sockinfo
            sock = socket.socket(si.get('family', socket.AF_INET),
                        si.get('type', socket.SOCK_STREAM), si.get('proto', 0))
            if self.timeout:
                sock.settimeout(self.timeout)
            sock.connect(si['addr'])
        else:
            sock = socket.create_connection((self.host, self.port))
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = wrap_socket(sock, **self.ssl_args)
