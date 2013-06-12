#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from bluepass.messagebus import *

from PySide.QtCore import (QEvent, QObject, QSocketNotifier, QTimer,
        QEventLoop)
from PySide.QtGui import QApplication


class CallbackEvent(QEvent):

    _evtype = QEvent.Type(QEvent.registerEventType())

    def __init__(self, callback, *args):
        super(CallbackEvent, self).__init__(self._evtype)
        self.callback = callback
        self.args = args


class QtIntegration(QObject):
    """Qt event loop integrate for our message bus."""

    READ = QSocketNotifier.Read
    WRITE = QSocketNotifier.Write

    def create_watch(self, socket, type, callback):
        socket.setblocking(0)
        notifier = QSocketNotifier(socket.fileno(), type, self)
        notifier.activated.connect(callback)
        notifier.setEnabled(True)
        return notifier

    def enable_watch(self, watch):
        if not watch.isEnabled():
            watch.setEnabled(True)

    def disable_watch(self, watch):
        if watch.isEnabled():
            watch.setEnabled(False)

    def create_timer(self, timeout, callback):
        timer = QTimer(self)
        timer.setInterval(timeout)
        timer.setSingleShot(True)
        timer.timeout.connect(callback)
        return timer

    def cancel_timer(self, timer):
        timer.stop()

    def create_callback(self, callback, *args):
        # Post an event to ourselves.
        event = CallbackEvent(callback, *args)
        QApplication.instance().postEvent(self, event)

    def event(self, event):
        # Called by the event loop.
        if isinstance(event, CallbackEvent):
            event.callback(*event.args)
            event.accept()
            return True
        else:
            event.ignore()
            return False


class QtMessageBusConnection(MessageBusConnectionBase):
    """Qt Message Bus connection.

    This adds Qt event loop integration. It also modifies call_method() so
    that if no callback is provided, we block until a reply is received.
    """

    Loop = QtIntegration

    def call_method(self, method, *args, **kwargs):
        """Call a method."""
        callback = kwargs.get('callback')
        if callback is not None:
            super(QtMessageBusConnection, self).call_method(method, *args, **kwargs)
            return
        replies = []
        def _store_reply(message):
            replies.append(message)
        kwargs['callback'] = _store_reply
        super(QtMessageBusConnection, self).call_method(method, *args, **kwargs)
        qapp = QApplication.instance()
        mask = QEventLoop.ExcludeUserInputEvents | QEventLoop.WaitForMoreEvents
        while True:
            qapp.processEvents(mask)
            if replies:
                break
        reply = replies[0]
        if reply['type'] == 'error':
            raise MessageBusError(reply['value']['error_name'], reply['value']['error_detail'])
        return reply['value']


class QtMessageBusHandler(MessageBusHandler):

    def __init__(self):
        super(QtMessageBusHandler, self).__init__()
        self.catchall_signal_handler = None

    def set_catchall_signal_handler(self, handler):
        self.catchall_signal_handler = handler

    def _dispatch_signal(self, message, connection):
        name = message.get('name')
        if name in self.signal_handlers:
            super(QtMessageBusHandler, self). \
                        _dispatch_signal(message, connection)
        elif self.catchall_signal_handler:
            self.catchall_signal_handler(message, connection)

    @method()
    def get_pairing_approval(self, name, vault, pin, kxid):
        mainwindow = QApplication.instance().mainWindow()
        def send_response(approved):
            self.connection.send_method_return(self.message, approved)
        mainwindow.showPairingApprovalDialog(name, vault, pin, kxid,
                                             send_response)
        self.delay_response()
