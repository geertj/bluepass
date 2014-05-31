#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from PyQt4.QtCore import QCoreApplication
from gruvi import jsonrpc

from support import *
from bluepass.frontends.qt import qjsonrpc
from bluepass.frontends.qt.qjsonrpc import *


try:
    from socket import socketpair
except ImportError:
    from gruvi.socketpair import socketpair


def echo_app(message, client):
    if not message.get('id'):
        return
    method = message.get('method')
    if not method or method != 'echo':
        return
    args = message.get('params', ())
    response = qjsonrpc.create_response(message, args)
    client.send_message(response)

def blackhole_app(message, client):
    pass

_notifications = []

def notify_app(message, client):
    method = message.get('method')
    if not method:
        return
    if not message.get('id'):
        _notifications.append((method, message.get('params', ())))
    elif method == 'get':
        response = qjsonrpc.create_response(message, _notifications)
        client.send_message(response)


class TestQJsonRpc(UnitTest):

    @classmethod
    def setUpClass(cls):
        super(TestQJsonRpc, cls).setUpClass()
        qapp = QCoreApplication.instance()
        if qapp is None:
            qapp = QCoreApplication([])
        cls.qapp = qapp

    def test_request(self):
        csock, ssock = socketpair()
        client = QJsonRpcClient()
        client.connect(csock)
        server = QJsonRpcClient(echo_app)
        server.connect(ssock)
        result = client.call_method('echo', 'foo')
        self.assertEqual(result, ['foo'])
        csock.close(); ssock.close()

    def test_request_timeout(self):
        csock, ssock = socketpair()
        client = QJsonRpcClient(timeout=0.1)
        self.assertEqual(client.timeout, 0.1)
        client.connect(csock)
        server = QJsonRpcClient(blackhole_app)
        server.connect(ssock)
        self.assertRaises(QJsonRpcError, client.call_method, 'echo', 'foo')
        csock.close(); ssock.close()

    def test_notification(self):
        csock, ssock = socketpair()
        client = QJsonRpcClient()
        client.connect(csock)
        server = QJsonRpcClient(notify_app)
        server.connect(ssock)
        client.send_notification('notify')
        client.send_notification('notify', 'foo')
        client.send_notification('notify', 'bar', 'baz')
        notifications = client.call_method('get')
        self.assertEqual(notifications, [['notify', []], ['notify', ['foo']],
                                         ['notify', ['bar', 'baz']]])
        csock.close(); ssock.close()


if __name__ == '__main__':
    unittest.main()
