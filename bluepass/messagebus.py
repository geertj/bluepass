#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import sys
import socket
import inspect
import traceback

from bluepass.error import StructuredError
from bluepass.platform import errno
from bluepass.util import json, logging

import gruvi

__all__ = ('MessageBusError', 'MessageBusConnectionBase',
           'MessageBusHandler', 'method', 'signal_handler')


class MessageBusError(StructuredError):
    """Message bus error."""


s_preamble, s_object, s_string, s_string_escape = range(4)

def find_message_end(buf):
    """Find the end of a JSON-RPC message."""
    state = s_preamble
    depth = 0
    for i in range(len(buf)):
        ch = buf[i]
        if state == s_preamble:
            if ch == '{':
                state = s_object
                depth = 1
            elif not ch.isspace():
                raise ValueError
        elif state == s_object:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            elif ch == '"':
                state = s_string
        elif state == s_string:
            if ch == '"':
                state = s_object
            elif ch == '\\':
                state = s_string_escape
        elif state == s_string_escape:
            state = s_string
        if state == s_object and depth == 0:
            return i
    return -1


class MessageBusConnectionBase(object):
    """Base class for a message bus connections.
    
    This class should not be instantiated itself, but rather a subclass
    that adds event loop integration.
    """

    timeout = 30
    max_message_size = 1024000
    max_incoming_messages = 100

    Loop = None
    Local = gruvi.local

    def __init__(self, socket, authtoken, handler=None, server=None):
        """Create a new message bus connection.
        
        The `socket` argument must be a connected socket and the `authtoken`
        argument must be the shared secret for hmac-magic-cookie-sha1
        authentication.  The `handler` argument, if provided, must be a
        MessageBusHandler instance that will be used to dispatch signals and
        method calls. If no handler is provided, signals and method calls to
        this connection end point will be ignored. The `server` argument, if
        provided, must be a MessageBusServer instance, and incidates that this
        connection is a server connection. Without a server argument this
        connection will be a client connection.
        """
        self.socket = socket
        self.authtoken = authtoken
        self.handler = handler
        self.server = server
        if self.server is None:
            self.name = str(socket.getsockname())
        else:
            self.name = self.server.name
        self.peer_name = str(socket.getpeername())
        self.next_serial = 1
        self.closed = False
        self.tracefile = None
        self.callbacks = []
        logger = logging.getLogger('bluepass.messagebus')
        context = 'connection %s:%s' % (self.name, self.peer_name)
        self.logger = logging.ContextLogger(logger, context)
        self.loop = self.Loop()
        self.method_calls = {}
        self._read_event = self.loop.create_watch(socket, self.loop.READ,
                                                  self._do_read)
        self._write_event = self.loop.create_watch(socket, self.loop.WRITE,
                                                   self._do_write)
        self._inbuf = self._outbuf = ''
        self._incoming = []; self._outgoing = []
        self._reading = self._writing = True

    def set_trace(self, tracefile):
        """Set a trace file."""
        self.tracefile = tracefile

    def add_callback(self, callback):
        """Add an event callback."""
        self.callbacks.append(callback)

    def _run_callbacks(self, event, *args):
        """Raise an event to all registered callbacks."""
        for callback in self.callbacks:
            callback(event, *args)

    def _do_trace(self, message, incoming):
        """Write a message to the trace file."""
        try:
            fout = file(self.tracefile, 'a')
        except IOError:
            return
        try:
            if incoming:
                fout.write('%s <- %s (incoming)\n' % (self.name, self.peer_name))
            else:
                fout.write('%s -> %s (outgoing)\n' % (self.name, self.peer_name))
            fout.write(message)
            fout.write('\n\n')
            fout.flush()
        except IOError:
            pass
        try:
            fout.close()
        except IOError:
            pass

    def _do_read(self):
        """Read messages from the socket and put them into the incoming queue
        until nothing more can be read."""
        logger = self.logger
        while True:
            while self._inbuf:
                pos = find_message_end(self._inbuf)
                if pos == -1:
                    break
                self._incoming.append(self._inbuf[:pos+1])
                if self.tracefile is not None:
                    self._do_trace(self._incoming[-1], True)
                self._inbuf = self._inbuf[pos+1:]
            if len(self._inbuf) > self.max_message_size:
                logger.debug('incoming message too large, closing connection')
                self.close()
                break
            if len(self._incoming) > self.max_incoming_messages:
                logger.debug('too many messages in incoming queue, throttling')
                self.loop.disable_watch(self._read_event)
                self._reading = False
                break
            try:
                buf = self.socket.recv(16384)
            except socket.error as e:
                if errno.is_wouldblock(e.errno):
                    break
                logger.error('recv() returned error: %s', str(e))
                self.close()
                break
            if buf == b'':
                logger.error('peer disconnected')
                self.close()
                break
            self._inbuf += buf.decode('utf8')
        if self._incoming:
            self.loop.create_callback(self.dispatch)

    def _do_write(self):
        """Drain message from the outgoing queue until we would block or until
        the queue is empty."""
        while True:
            if not self._outbuf:
                if not self._outgoing:
                    break
                if self.tracefile is not None:
                    self._do_trace(self._outgoing[0], False)
                self._outbuf = self._outgoing.pop(0).encode('utf8')
            try:
                nbytes = self.socket.send(self._outbuf)
            except socket.error as e:
                if errno.is_wouldblock(e.errno):
                    break
                self.logger.error('send() returned error: %s', str(e))
                self.close()
                break
            self._outbuf = self._outbuf[nbytes:]
        if not self._outbuf:
            self.loop.disable_watch(self._write_event)
            self._writing = False

    def check_message(self, message):
        """Check that an incoming message is valid."""
        logger = self.logger
        try:
            u = json.unpack(message, '{s:s}', ('jsonrpc',))
        except json.UnpackError as e:
            logger.error('illegal incoming message: %s', str(e))
            return False
        if u[0] != '2.0':
            logger.error('Illegal incoming message')
            return False
        return True

    def close(self):
        """Close the connection."""
        if self.closed:
            return
        self.loop.disable_watch(self._read_event)
        self.loop.disable_watch(self._write_event)
        self.logger.debug('closing connection')
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except socket.error:
            pass
        try:
            self.socket.close()
        except socket.error:
            pass
        self.logger.debug('connection closed')
        self.closed = True
        self._run_callbacks('ConnectionClosed', self)

    def push_outgoing(self, message):
        """Push a message onto the outgoing queue."""
        if not isinstance(message, dict):
            raise TypeError('expecting a dictionary')
        serialized = json.dumps(message, indent=2)
        self._outgoing.append(serialized)
        if not self.closed and not self._writing:
            self.loop.enable_watch(self._write_event)
            self._writing = True

    def pop_incoming(self):
        """Pop a message from the incoming queue. Returns None if no
        message is available."""
        if not self._incoming:
            return
        serialized = self._incoming.pop(0)
        message = json.try_loads(serialized, dict)
        if message is None or not self.check_message(message):
            self.logger.error('invalid input message')
            self.close()
            return
        if not self._reading and not self.closed and \
                    len(self._incoming) < self.max_incoming_messages:
            self.logger.debug('removing read throttle')
            self.loop.enable_watch(self._read_event)
            self._reading = True
        return message

    def send_method_return(self, message, value, **kwargs):
        """Send a method return in response to the method call `msg`."""
        if not isinstance(message, dict):
            raise TypeError('Expecing a dict instance for "message"')
        reply = { 'jsonrpc': '2.0' }
        reply['id'] = message['id']
        reply['result'] = value
        self.push_outgoing(reply, **kwargs)

    def send_error(self, message, error, **kwargs):
        """Send an error message in response to the method call `msg`."""
        if not isinstance(message, dict):
            raise TypeError('Expecting a dict instance for "message"')
        if not isinstance(error, StructuredError):
            raise TypeError('Expecting a StructuredError instance for "error"')
        reply = { 'jsonrpc': '2.0' }
        reply['id'] = message['id']
        reply['error'] = error.asdict()
        self.push_outgoing(reply, **kwargs)

    def send_signal(self, signal, *args, **kwargs):
        """Emit a signal."""
        message = { 'jsonrpc': '2.0' }
        message['method'] = signal
        message['params'] = args
        self.push_outgoing(message, **kwargs)

    def dispatch(self):
        """Dispatch message from the connection."""
        logger = self.logger
        while True:
            message = self.pop_incoming()
            if not message:
                break
            if 'result' in message or 'error' in message:
                key = message['id']
                callback = self.method_calls.pop(key, None)
                if callback:
                    self.loop.create_callback(callback, message)
            elif self.handler:
                self.spawn(self.handler.dispatch, message, self)
            else:
                logger.info('no handler, cannot handle incoming message')

    def spawn(self, handler, *args):
        """Spawn a handler. Can be overrided in a subclass."""
        handler(*args)

    def call_method(self, method, *args, **kwargs):
        """Call a method. If a `callback` argument is specified, it is
        invoked when this method returns."""
        message = { 'jsonrpc': '2.0' }
        message['id'] = self.next_serial
        self.next_serial += 1
        message['method'] = method
        message['params'] = args
        self.push_outgoing(message)
        callback = kwargs.get('callback')
        if callback is None:
            return
        def method_return_callback(reply=None):
            if reply is None:
                # timeout
                error = { 'jsonrpc': '2.0' }
                error['id'] = message['id']
                err = StructuredError('Timeout', 'Method call timed out')
                error['error'] = err.asdict()
                del self.method_calls[message['id']]
                callback(error)
            else:
                self.loop.cancel_timer(timer)
                callback(reply)
        timeout = kwargs.get('timeout', self.timeout)
        timer = self.loop.create_timer(timeout, method_return_callback)
        self.method_calls[message['id']] = method_return_callback


def method(**kwargs):
    """Decorator to expose a method in a MessageBusHandler class."""
    def decorate(func):
        func.method = True
        func.name = func.__name__
        for key,value in kwargs.items():
            setattr(func, key, value)
        return func
    return decorate

def signal_handler(**kwargs):
    """Decorator to install a signal handler in a MessageBusHandler class."""
    def decorate(func):
        func.signal_handler = True
        func.name = func.__name__
        for key,value in kwargs.iteritems():
            setattr(func, key, value)
        return func
    return decorate


class MessageBusHandler(object):
    """A handler to handle incoming messages on a message bus.

    There will be just one instance of this handler across all message bus
    connections. This allows us to more easily share state across the different
    frontend connections. Connection specific data needs to be stored in the
    "local" attribute which is a gruvi "local.local" object.
    """

    def __init__(self):
        """Constructor."""
        self.methods = {}
        self.signal_handlers = {}
        self.logger = logging.getLogger(__name__)
        self._init_handlers()

    def _init_handlers(self):
        """Load method and signal handlers.
        
        The method and signal handlers are methods of this class that
        have been decorated with @method and @signal_handler respectively.
        """
        for name in vars(self.__class__):
            handler = getattr(self, name)
            if getattr(handler, 'method', False):
                self.methods[handler.name] = handler
            elif getattr(handler, 'signal_handler', False):
                self.signal_handlers[handler.name] = handler

    def _get_message(self):
        return self.local.message

    message = property(_get_message)

    def _get_connection(self):
        return self.local.connection

    connection = property(_get_connection)

    def _check_callable(self, handler, args):
        """Check that `handler` can be called as handler(*args)."""
        if not callable(handler):
            return False
        spec = inspect.getargspec(handler)
        minargs = len(spec.args)
        if spec.defaults:
            minargs -= len(spec.defaults)
        if spec.varargs:
            maxargs = None
        else:
            maxargs = len(spec.args)
        minargs -= 1  # Adjust for "self"
        if maxargs:
            maxargs -= 1
        return len(args) >= minargs and (maxargs is None or len(args) <= maxargs)

    def _dispatch_method_call(self, message, connection):
        """Dispatch a method call."""
        logger = self.logger
        name = message['method']
        if name not in self.methods:
            error = MessageBusError('NotFound', 'No such method call: {}'.format(name))
            connection.send_error(message, error)
            return
        handler = self.methods[name]
        args = message.get('params', ())
        if not self._check_callable(handler, args):
            logger.error('wrong # of arguments for method %s', name)
            error = MessageBusError('InvalidCall', 'Wrong number of arguments')
            connection.send_error(message, error)
            return
        self.local.response_sent = False
        try:
            response = handler(*args)
        except StructuredError as e:
            connection.send_error(message, e)
            return
        except Exception:
            lines = ['Uncaught exception in method call handler\n']
            lines += traceback.format_exception(*sys.exc_info())
            logger.error(''.join(lines))
            error = MessageBusError('UncaughtException')
            connection.send_error(message, error)
            return
        if not self.local.response_sent:
            connection.send_method_return(message, response)

    def _dispatch_signal(self, message, connection):
        """Dispatch a signal."""
        logger = self.logger
        name = message.get('method')
        if name not in self.signal_handlers:
            return
        handler = self.signal_handlers[name]
        args = message.get('params', ())
        if not self._check_callable(handler, args):
            logger.error('wrong # of arguments for signal handler %s', name)
            return
        try:
            handler(*args)
        except Exception:
            lines = ['Uncaught exception in signal handler\n']
            lines += traceback.format_exception(*sys.exc_info())
            logger.error(''.join(lines))

    def dispatch(self, message, connection):
        """Dispatch a message."""
        if not hasattr(self, 'local'):
            self.local = connection.Local()
        self.local.message = message
        self.local.connection = connection
        if message.get('id') is not None and 'method' in message:
            self._dispatch_method_call(message, connection)
        elif message.get('id') is None and 'method' in message:
            self._dispatch_signal(message, connection)

    def early_response(self, value=None):
        """Send an early method call response.
        
        An early method call responses is a response where the handler needs to
        continue some (potentially time-consuming) work and you do not want to
        wait for that before sending the response.
        """
        if 'id' not in self.message:
            raise RuntimeError('You cannot use send_reponse() for a signal')
        self.connection.send_method_return(self.message, value)
        self.local.response_sent = True

    def delay_response(self):
        """Delay the response for this method call.

        A delayed responses is a response where the response value cannot yet
        be generated at the time the handler returns. It is the responsbility
        of the caller to send the response later.
        """
        if 'id' not in self.message:
            raise RuntimeError('You cannot use delay_response() for a signal')
        self.local.response_sent = True
