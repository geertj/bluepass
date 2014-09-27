#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import gruvi
from gruvi import jsonrpc
from bluepass import validate, logging

__all__ = ['method', 'notification', 'anonymous', 'JsonRpcHandler']


def method(params=None, name=None):
    """Return a decorator that marks a method handler."""
    def decorate(func):
        func.params = params
        func.validate_params = params and validate.compile(params)
        func.method_name = name or func.__name__
        func.jsonrpc_handler = 'method'
        return func
    return decorate

def notification(params=None, name=None):
    """Return a decorator that marks a notification handler."""
    def decorate(func):
        func.params = params
        func.validate_params = params and validate.compile(params)
        func.method_name = name or func.__name__
        func.jsonrpc_handler = 'notification'
        return func
    return decorate

def anonymous(func):
    func.anonymous = True
    return func


class JsonRpcHandler(object):
    """JSON-RPC procotol handler."""

    def __init__(self):
        self._log = logging.get_logger(self)
        self._local = gruvi.local()
        self._init_handlers()

    def _init_handlers(self):
        self._method_handlers = []
        self._notification_handlers = []
        for name in dir(self):
            try:
                handler = getattr(self, name)
            except AttributeError:
                continue  # unitialized property
            if not callable(handler) or not hasattr(handler, 'jsonrpc_handler'):
                continue
            if not hasattr(handler, 'anonymous'):
                handler.__func__.anonymous = False
            if handler.jsonrpc_handler == 'method':
                self._method_handlers.append(handler)
            elif handler.jsonrpc_handler == 'notification':
                self._notification_handlers.append(handler)

    def authenticate(self):
        """Authenticate the request."""

    def handle_error(self):
        """Handle an uncaught exception."""

    @property
    def message(self):
        return self._local.message
    
    @property
    def transport(self):
        return self._local.transport

    @property
    def protocol(self):
        return self._local.protocol

    def send_response(self, result):
        response = jsonrpc.create_response(self.message, result)
        self.protocol.send_message(response)

    def send_notification(self, name, *args):
        message = jsonrpc.create_notification(name, args)
        self.protocol.send_message(self.transport, message)

    def _new_request(self, message, protocol, transport):
        self._local.message = message
        self._local.protocol = protocol
        self._local.transport = transport

    def __call__(self, message, transport, protocol):
        method = message.get('method')
        if method is None:
            self._log.error('message without "method"')
            return
        self._log.debug('new {}: {}', jsonrpc.message_type(message), method)
        # Find the right handler
        if message.get('id') is None:
            handlers = self._notification_handlers
        else:
            handlers = self._method_handlers
        for handler in handlers:
            if handler.method_name == method:
                break
        else:
            self._log.error('no handler found')
            return jsonrpc.create_error(message, jsonrpc.METHOD_NOT_FOUND)
        # Set local data and authenticate
        self._new_request(message, protocol, transport)
        if not handler.anonymous and not self.authenticate():
            self._log.error('connection is not authenticated')
            return jsonrpc.create_error(message, jsonrpc.SERVER_ERROR, 'Not Authenticated')
        # Validate parameters
        params = message.get('params', [])
        validator = handler.validate_params
        if validator:
            vres = validator.validate(params)
            if not vres:
                self._log.error('parameter validation failed: {}', vres.error)
                return jsonrpc.create_error(message, jsonrpc.INVALID_PARAMS, vres.error)
        # Call into the handler!
        try:
            result = handler(*params)
        except Exception as e:
            self._log.exception('exception in handler')
            return self.create_error(message, e)
        self._log.debug('handler completed succesfully')
        self.send_response(result)
