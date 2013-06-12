#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import gevent
from gevent import socket
import subprocess
from subprocess import PIPE

from bluepass import crypto
from bluepass.util.ssl import SSLSocket
from bluepass.test.unit import UnitTest


class TestSSL(UnitTest):

    def _create_certificate(self, fname, subject):
        ret = subprocess.call(['openssl', 'req', '-new', '-newkey',
                'rsa:1024', '-x509', '-subj', subject, '-days', '365',
                '-nodes', '-out', fname, '-keyout', fname],
                stdout=PIPE, stderr=PIPE)
        if ret != 0:
            raise RuntimeError('Failed to generated certificate')
        return fname

    def test_channel_binding(self):
        self._create_certificate('server.pem', '/CN=foo/')
        cb = []; data = []
        def server(sock):
            conn, addr = sock.accept()
            sslsock = SSLSocket(conn, server_side=True,
                             keyfile='server.pem', certfile='server.pem')
            cb.append(sslsock.get_channel_binding())
            buf = sslsock.read()
            data.append(buf)
            conn = sslsock.unwrap()
            conn.close()
        def client(sock, addr):
            sock.connect(addr)
            sslsock = SSLSocket(sock)
            cb.append(sslsock.get_channel_binding())
            sslsock.write('foo')
            data.append('foo')
            sslsock.unwrap()
        s1 = socket.socket()
        s1.bind(('localhost', 0))
        s1.listen(2)
        s2 = socket.socket()
        g1 = gevent.spawn(server, s1)
        g2 = gevent.spawn(client, s2, s1.getsockname())
        gevent.joinall([g1, g2])
        s1.close(); s2.close()
        assert len(cb) == 2
        assert len(cb[0]) in (12, 36)
        assert cb[0] == cb[1]
        assert len(data) == 2
        assert data[0] == data[1]

    def test_anon_dh(self):
        dhparams = crypto.dhparams['skip2048']
        data = []; ciphers = []; cb = []
        def server(sock):
            conn, addr = sock.accept()
            sslsock = SSLSocket(conn, server_side=True,
                                  dhparams=dhparams, ciphers='ADH+AES')
            buf = sslsock.read()
            data.append(buf)
            ciphers.append(sslsock.cipher())
            cb.append(sslsock.get_channel_binding())
            conn = sslsock.unwrap()
            conn.close()
        def client(sock, addr):
            sock.connect(addr)
            sslsock = SSLSocket(sock, ciphers='ADH+AES')
            sslsock.write('foo')
            data.append('foo')
            ciphers.append(sslsock.cipher())
            cb.append(sslsock.get_channel_binding())
            sslsock.unwrap()
        s1 = socket.socket()
        s1.bind(('localhost', 0))
        s1.listen(2)
        s2 = socket.socket()
        g1 = gevent.spawn(server, s1)
        g2 = gevent.spawn(client, s2, s1.getsockname())
        gevent.joinall([g1, g2])
        s1.close(); s2.close()
        assert len(data) == 2
        assert len(data[0]) > 0
        assert data[0] == data[1]
        assert len(ciphers) == 2
        assert len(ciphers[0]) > 0
        assert ciphers[0] == ciphers[1]
        assert 'ADH' in ciphers[0][0]
        assert len(cb) == 2
        assert len(cb[0]) in (12, 36)
        assert cb[0] == cb[1]
