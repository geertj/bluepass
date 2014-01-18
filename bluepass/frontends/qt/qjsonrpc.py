#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import json
import errno
import socket
import collections
import fnmatch

from PyQt4.QtCore import (QEvent, QObject, QSocketNotifier, QTimer, QEventLoop,
                          QCoreApplication)

from gruvi import jsonrpc
from bluepass import platform, util, logging


__all__ = ['QJsonRpcError', 'QJsonRpcClient', 'QJsonRpcHandler', 'request',
           'notification']

# re-export these to our consumers as module-level objects
from gruvi.jsonrpc import (create_request, create_response, create_error,
                           create_notification)


class _Dispatch(QEvent):
    """Event used by QJsonRpcClient to start dispatching messages."""

    _evtype = QEvent.Type(QEvent.registerEventType())

    def __init__(self):
        super(_Dispatch, self).__init__(self._evtype)


class QJsonRpcError(Exception):
    pass


class QJsonRpcClient(QObject):
    """A JSON-RPC client integrated with the Qt event loop."""

    default_timeout = 5

    def __init__(self, message_handler=None, timeout=-1, parent=None):
        """Create a new message bus connection.

        The *handler* specifies an optional message handler.
        """
        super(QJsonRpcClient, self).__init__(parent)
        self._message_handler = message_handler
        self._timeout = timeout if timeout != -1 else self.default_timeout
        self._socket = None
        self._method_calls = {}
        self._outbuf = b''
        self._incoming = collections.deque()
        self._outgoing = collections.deque()
        self._parser = jsonrpc.JsonRpcParser()
        self._read_notifier = None
        self._write_notifier = None
        self._log = logging.get_logger(self)

    @property
    def timeout(self):
        return self._timeout

    def connect(self, address):
        """Connect to a JSON-RPC server at *address*."""
        sock = util.create_connection(address, self._timeout)
        sock.settimeout(0)
        self._read_notifier = QSocketNotifier(sock.fileno(), QSocketNotifier.Read, self)
        self._read_notifier.activated.connect(self._do_read)
        self._read_notifier.setEnabled(True)
        self._write_notifier = QSocketNotifier(sock.fileno(), QSocketNotifier.Write, self)
        self._write_notifier.activated.connect(self._do_write)
        self._write_notifier.setEnabled(False)
        self._socket = sock

    def _do_read(self):
        # Read messages from the socket and put them into the incoming queue
        # until nothing more can be read.
        while True:
            try:
                buf = self._socket.recv(4096)
            except socket.error as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                self._log.error('recv() error {0}'.format(e.errno))
                self.close()
                break
            if buf == b'':
                self._log.error('peer closed connection')
                self.close()
                break
            nbytes = self._parser.feed(buf)
            if nbytes != len(buf):
                self._log.error('parse error {0}'.format(self._parser.error))
                self.close()
                break
            while True:
                message = self._parser.pop_message()
                if not message:
                    break
                self._incoming.append(message)
        # Schedule a dispatch if there are incoming messages
        if self._incoming:
            QCoreApplication.instance().postEvent(self, _Dispatch())

    def _do_write(self):
        # Drain message from the outgoing queue until we would block or until
        # the queue is empty.
        while True:
            if not self._outbuf:
                if not self._outgoing:
                    break
                message = self._outgoing.popleft()
                self._outbuf = json.dumps(message).encode('utf8')
            try:
                nbytes = self._socket.send(self._outbuf)
            except socket.error as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                self.logger.error('send() error {0}'.format(e.errno))
                self.close()
                break
            self._outbuf = self._outbuf[nbytes:]
        if not self._outbuf:
            self._write_notifier.setEnabled(False)

    def close(self):
        """Close the connection."""
        if self._socket is None:
            return
        self._read_notifier.setEnabled(False)
        self._write_notifier.setEnabled(False)
        try:
            self._socket.close()
        except socket.error:
            pass
        self._log.debug('connection closed')
        self._socket = None

    def send_message(self, message):
        """Send a raw JSON-RPC message."""
        if self._socket is None:
            raise RuntimeError('not connected')
        if not jsonrpc.check_message(message):
            raise ValueError('invalid JSON-RPC message')
        self._outgoing.append(message)
        if not self._write_notifier.isEnabled():
            self._write_notifier.setEnabled(True)

    def send_notification(self, method, *args):
        """Send a JSON-RPC notification."""
        message = jsonrpc.create_notification(method, args)
        self.send_message(message)

    def event(self, event):
        # Process the DispatchMessages event
        if isinstance(event, _Dispatch):
            self._dispatch()
            event.accept()
            return True
        else:
            event.ignore()
            return False

    def _dispatch(self):
        # Dispatch message from the connection.
        while self._incoming:
            message = self._incoming.popleft()
            if 'result' in message or 'error' in message:
                # response
                key = message['id']
                callback = self._method_calls.get(key, None)
                if callback:
                    callback(message, self)
            elif self._message_handler:
                self._message_handler(message, self)
            else:
                self._log.info('no handler, cannot handle incoming message')

    def call_method(self, method, *args, **kwargs):
        """Call a method."""
        if self._method_calls:
            raise RuntimeError('recursive call_method() detected')
        message = jsonrpc.create_request(method, args)
        self.send_message(message)
        replies = []
        def method_response(message, client):
            replies.append(message)
        def method_timeout():
            reply = jsonrpc.create_error(message, jsonrpc.SERVER_ERROR,
                                        'Method call timed out')
            replies.append(reply)
        timeout = kwargs.pop('timeout', self.timeout)
        if timeout:
            timer = QTimer(self)
            timer.setInterval(timeout*1000)
            timer.setSingleShot(True)
            timer.timeout.connect(method_timeout)
            timer.start()
        # Run an embedded event loop to process network events until we get a
        # response. We allow only one concurrent call so that we don't run the
        # risk of overflowing the stack.
        self._method_calls[message['id']] = method_response
        loop = QEventLoop()
        mask = QEventLoop.ExcludeUserInputEvents | QEventLoop.WaitForMoreEvents
        while True:
            loop.processEvents(mask)
            if replies:
                break
        if timeout:
            timer.stop()
        reply = replies[0]
        del self._method_calls[message['id']]
        if reply.get('error'):
            raise QJsonRpcError(reply['error'])
        self.message = reply
        return reply.get('result')


def request(name=None):
    """Return a decorator that marks a function as a request handler."""
    def decorate(handler):
        handler.request = True
        handler.name = name or handler.__name__
        return handler
    return decorate

def notification(name=None):
    """Return a decorator that marks a function as a notification handler."""
    def decorate(handler):
        handler.notification = True
        handler.name = name or handler.__name__
        return handler
    return decorate


class QJsonRpcHandler(object):
    """An object based message handler.

    Methods on instances can be decorated with :func:`request` or
    :func:`notification` to mark them as request and notificaiton handlers
    respectively.
    """

    def __init__(self):
        self._request_handlers = []
        self._notification_handlers = []
        self._init_handlers()

    def _init_handlers(self):
        for sym in dir(self):
            handler = getattr(self, sym)
            if getattr(handler, 'request', False):
                self._request_handlers.append(handler)
            elif getattr(handler, 'notification', False):
                self._notification_handlers.append(handler)

    def __call__(self, message, client):
        method = message.get('method')
        if not method:
            return
        is_request = (message.get('id') is not None)
        if is_request:
            handlers = self._request_handlers
        else:
            handlers = self._notification_handlers
        handlers_found = 0
        for handler in handlers:
            if not fnmatch.fnmatch(method, handler.name):
                continue
            handlers_found += 1
            args = message.get('params', ())
            self.message = message
            self.client = client
            self.send_response = True
            result = exc = None
            try:
                result = handler(*args)
            except Exception as e:
                client._log.exception('uncaught exception in handler')
                exc = e
            self.message = None
            self.client = None
            if not is_request:
                continue
            if exc:
                response = jsonrpc.create_error(message, jsonrpc.INTERNAL_ERROR)
            elif self.send_response:
                response = jsonrpc.create_response(message, result)
            else:
                response = None
            if response:
                client.send_message(response)
            break
        if is_request and handlers_found == 0:
            error = jsonrpc.create_error(message, jsonrpc.METHOD_NOT_FOUND)
            client.send_message(error)
