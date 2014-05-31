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

__all__ = ['route', 'RpcError', 'RpcHandler']


def route(method=None, args=None, request_type='methodcall'):
    """Return a decorator that marks a method as a RPC request handler.

    The *method* argument specifies the name of the RPC method to route to the
    handler. By default it will be the ``__name__`` of the method that is being
    decorated.

    The *args* argument specifies a :mod:`jsonkit` validator expression that is
    used to check the arguments. An example such a validator expression is
    ``[int, int]``, which would ensure that a method is called with two integer
    arguments.

    The *request_type* parameter specifies the request type to route to the
    handler. This can either be ``'methodcall'``, to route only method calls,
    ``'notification'``, to route only notifications, or ``None`` to route any
    message to the handler.
    """
    def decorate(func):
        func.method = method or func.__name__
        func.args = validate.compile(args) if args else None
        func.request_type = request_type
        return func
    return decorate


class RpcError(Exception):
    """RPC error.

    This exception can be used to have :class:`RpcHandler` return a specific
    JSON-RPC error message.
    """

    def __init__(self, message, code=jsonrpc.INVALID_REQUEST, data=None):
        super(RpcError, self).__init__(message, code, data)

    message = property(lambda self: self.args[0])
    code = property(lambda self: self.args[1])
    data = property(lambda self: self.args[2])


class RpcHandler(object):
    """RPC handler

    This class implements a very small (pico?) framework for building RPC
    services and exposing them via Gruvi's :class:`gruvi.JsonRpcServer`.

    To use this class, define methods and decorate them using the :func:`route`
    decorator. When an incoming method call or notification occurs, the
    framework will route it to the appropriate method. The method will be
    called with the position arguments from the JSON-RPC request.

    If no method is found, the :meth:`method_not_found` method will be called.
    You can override this method to respond to methods for which no route is
    present.

    The framework supports pre- and post-request hooks using
    :meth:`pre_request_hook` and :meth:`post_request_hook`, respectively.

    Uncaught exceptions can be intercepted by defining
    :meth:`uncaught_exception`.

    To use this class, pass an instance of it as the *message_handler* argument
    to :class:`gruvi.JsonRpcServer`.
    """

    Local = gruvi.local

    def __init__(self):
        self._log = logging.get_logger()
        self._local = self.Local()
        self._init_routes()

    def _init_routes(self):
        # Initialize routes that were established by the @route decorator.
        routes = {}
        for name in dir(self):
            try:
                handler = getattr(self, name)
            except AttributeError:
                continue  # unitialized property
            if not callable(handler):
                continue
            method = getattr(handler, 'method', None)
            if method is None:
                continue
            routes[method] = handler
        self._routes = routes

    def pre_request_hook(self, method, *params):
        """Pre-request hook.

        This hook is called prior to validating the parameters and calling out
        to the request handler.

        The *method* argument is the name of the method that is called. It is
        followed by any positional arguments.

        This method should not return anything, but may raise a
        :class:`RpcError` to abort processing this request.
        """

    def post_request_hook(self, result):
        """Post-request hook.

        This hook is called after the request handler has been called. The
        *result* parameter is the return value of the handler.

        This method should not return anything, but may raise a
        :class:`RpcError` to abort processing this request.
        """

    def uncaught_exception(self, exc):
        """Uncaught exception hook.

        This method is called when an uncaught exception occurs. The exception
        is passed as the *exc* argument.

        This method must either raise a :class:`RpcError`, or return. If this
        method returns then the original exception will be re-raised.
        """

    def method_not_found(self, method, *args):
        """Method not found handler.

        This handler will be used if there is no route for the incoming method
        call or notification.

        The default implementation raises a :class:`RpcError` with a
        *code* of ``jsonrpc.METHOD_NOT_FOUND``.
        """
        raise RpcError(code=jsonrpc.METHOD_NOT_FOUND)

    @property
    def log(self):
        """A connection specific logger."""
        return self._log

    @property
    def data(self):
        """A dictionary that can be used to store per-connection data."""
        if not hasattr(self._local, 'data'):
            self._local.data = {}
        return self._local.data

    @property
    def message(self):
        """The parsed JSON-RPC message of the current request (a dict instance)."""
        return self._local.message

    @property
    def transport(self):
        """The :class:`gruvi.Transport` instance for this connection."""
        return self._local.transport

    @property
    def protocol(self):
        """The :class:`gruvi.JsonRpcProtocol` instance for this connection."""
        return self._local.protocol

    def delay_response(self):
        self._local.delay_response = True

    def __call__(self, message, transport, protocol):
        # Handle a new request. This is the handler called by JsonRpcProtocol.
        method = message.get('method')
        if method is None:
            return
        mtype = jsonrpc.message_type(message)
        ismethod = mtype == 'methodcall'
        # Find the right handler
        handler = self._routes.get(method)
        if handler and (handler.request_type is None or handler.request_type != mtype):
            handler = None
        # Export request data to handlers
        self._local.message = message
        self._local.protocol = protocol
        self._local.transport = transport
        self._local.delay_response = False
        # Call into the handlers
        try:
            try:
                params = message.get('params', [])
                self.pre_request_hook(method, *params)
                if handler:
                    if handler.args:
                        handler.args.validate(params)
                    result = handler(*params)
                else:
                    result = self.method_not_found(method, *params)
                if result is not None and not ismethod:
                    self._log.warning('handler returned a value for notification')
                if ismethod:
                    response = jsonrpc.create_response(message, result)
                self.post_request_hook(result)
            except Exception as e:
                self.uncaught_exception(e)
                raise
        except RpcError as e:
            response = jsonrpc.create_error(message, e.code, e.message, e.data)
        except Exception as e:
            response = jsonrpc.create_error(message, jsonrpc.SERVER_ERROR)
        if ismethod and not self._local.delay_response:
            self.protocol.send_message(response)
