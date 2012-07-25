#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import os
import random

import gevent
from gevent import socket
from bluepass.messagebus import *
from bluepass.test.unit import UnitTest, assert_raises


class ServerHandler(MessageBusHandler):

    @method()
    def echo(self, *args):
        return args

    @method()
    def nested_echo(self, *args):
        return self.connection.call_method('client_echo', *args)

    @signal_handler(spawn=None)
    def mysignal(self, signal):
        self.signal = signal

    @method()
    def getsignal(self):
        return self.signal

    @method()
    def set_value(self, value):
        self.value = value

    @method()
    def get_value(self):
        return self.value


class ClientHandler(MessageBusHandler):

    @method()
    def client_echo(self, *args):
        return args


class TestMessageBus(UnitTest):

    @classmethod
    def setup_class(cls):
        super(TestMessageBus, cls).setup_class()
        lsock = socket.socket()
        lsock.bind(('0.0.0.0', 0))
        lsock.listen(2)
        cls.address = lsock.getsockname()
        cls.authtok = os.urandom(16).encode('hex')
        handler = ServerHandler()
        cls.server = MessageBusServer(lsock, cls.authtok, handler=handler)
        cls.server.start()
        cls.server.set_trace('/tmp/server.txt')
        csock = socket.socket()
        csock.connect(cls.address)
        handler = ClientHandler()
        cls.client = MessageBusConnection(csock, cls.authtok, handler=handler)
        cls.client.set_trace('/tmp/client.txt')

    @classmethod
    def teardown_class(cls):
        super(TestMessageBus, cls).teardown_class()
        cls.server.stop()

    def test_call_method(self):
        reply = self.client.call_method('echo', 'foo', 'bar')
        assert reply == ['foo', 'bar']

    def test_nested_call_method(self):
        reply = self.client.call_method('nested_echo', 'foo', 'bar')
        assert reply == ['foo', 'bar']

    def test_signal(self):
        self.client.send_signal('mysignal', 'foo')
        gevent.sleep(1)  # order between signal and method_call is not guaranteed
        reply = self.client.call_method('getsignal')
        assert reply == 'foo'

    def test_arg_count(self):
        reply = self.client.call_method('set_value', 10)
        assert reply is None
        err = assert_raises(MessageBusError, self.client.call_method, 'set_value')
        assert err[0] == 'InvalidCall'
        err = assert_raises(MessageBusError, self.client.call_method, 'set_value', 10, 20)
        assert err[0] == 'InvalidCall'

    def test_arg_type_none(self):
        reply = self.client.call_method('echo', None)
        assert reply == [None,]

    def test_arg_type_bool(self):
        for value in (False, True):
            reply = self.client.call_method('echo', value)
            assert reply == [value,]

    def test_arg_type_int(self):
        for value in (-1000, -1, 0, 1, 1000):
            reply = self.client.call_method('echo', value)
            assert reply == [value,]

    def test_arg_type_float(self):
        for value in (-1000.1, -1.1, 0.0, 1.1, 1000.1):
            reply = self.client.call_method('echo', value)
            assert reply == [value,]

    def test_arg_type_string(self):
        for value in ('foo', 'bar', 'baz'):
            reply = self.client.call_method('echo', value)
            assert reply == [value,]

    def test_arg_type_unicode(self):
        for value in (u'\u20ac20,-', u'b\u00e1r'):
            reply = self.client.call_method('echo', value)
            assert reply == [value,]

    def test_mutiple_clients(self):
        csock1 = socket.socket()
        csock1.connect(self.address)
        client1 = MessageBusConnection(csock1, self.authtok)
        csock2 = socket.socket()
        csock2.connect(self.address)
        client2 = MessageBusConnection(csock2, self.authtok)
        client1.call_method('set_value', 10)
        reply = client2.call_method('get_value')
        assert reply == 10
        client1.close()
        client2.close()

    def test_multiple_calls(self):
        self.client.call_method('set_value', 20)
        for i in range(100):
            reply = self.client.call_method('get_value')
            assert reply == 20
