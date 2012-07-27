#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012 by Geert
# Jansen. All rights are reserved.

import os
import socket
import logging

from bluepass import platform
from bluepass.factory import create, instance, deref, FactoryError
from bluepass.crypto import CryptoProvider
from bluepass.database import Database
from bluepass.model import Model
from bluepass.passwords import PasswordGenerator
from bluepass.locator import Locator, ZeroconfLocationSource
from bluepass.messagebus import MessageBusServer
from bluepass.socketapi import SocketAPIHandler
from bluepass.syncapi import SyncAPIApplication, SyncAPIServer, SyncAPIPublisher
from bluepass.syncer import Syncer


# The two functions below are the only entry points that the frontend
# needs into the backend.

# Available options:
#  debug: True|False
#  trace: True|False
#  log_stdout: True|False
#  datadir: string
#  syncport: int
 
def start_backend(timeout, options=None):
    """Start the backend. Returns a tuple (status, detail).  If status == True,
    the backend was started, and detail is the tuple (ipaddr, port, authtok).
    If status == False, the backend did not start up correctly, and detail is
    a tuple (error_name, error_message).
    """
    try:
        backend = instance(Backend)
    except FactoryError:
        pass
    else:
        detail = ('Exists', 'Backend already running')
        return (False, detail)
    backend = create(Backend, options)
    status = backend.start(timeout)
    if status:
        detail = (backend.ipaddr, backend.port, backend.authtok)
    else:
        detail = (backend.error_name, backend.error_message,
                  backend.error_detail)
    return (status, detail)

def stop_backend(timeout):
    """Stop the backend. Returns True if the backend was stopped
    succesfully within the timeout, or False otherwise."""
    backend = instance(Backend)
    status = backend.stop(timeout)
    deref(Backend)
    return status


class Backend(object):
    """The Bluepass backend. This is an active component that runs as a
    separate process (or thread on Windows). It communicates with the frontend
    via a socket (the message bus)."""

    def __init__(self, options=None):
        """Constructor."""
        self.options = options or {}
        self.datadir = options.get('datadir')
        if self.datadir is None:
            self.datadir = platform.get_appdir('bluepass')
        sock = socket.socket()
        sock.bind(('localhost', 0))
        sock.listen(2)
        sock.setblocking(0)
        self.listener = sock
        self.ipaddr, self.port = sock.getsockname()
        crypto = CryptoProvider()
        self.authtok = crypto.random(16).encode('hex')
        if options.get('trace'):
            self.tracefile = os.path.join(self.datadir, 'backend.trace')
        else:
            self.tracefile = None
        self.logger = logging.getLogger('bluepass.backend')

    def _start_backend(self):
        """Start up all backend components."""
        crypto = create(CryptoProvider)
        fname = os.path.join(self.datadir, 'bluepass.db')
        database = create(Database, fname)
        database.lock()
        model = create(Model, database)
        locator = create(Locator)
        zeroconf = create(ZeroconfLocationSource)
        if zeroconf:
            locator.add_source(zeroconf)
        passwords = create(PasswordGenerator)
        listener = socket.socket()
        listener.bind(('0.0.0.0', 0))
        listener.listen(2)
        listener.setblocking(0)
        app = create(SyncAPIApplication)
        syncapi = create(SyncAPIServer, listener, app)
        syncapi.start()
        publisher = create(SyncAPIPublisher, syncapi)
        publisher.start()
        # The syncer is started at +10 seconds so that the locator will have
        # hopefully located all neighbors by then and we can do a once-off
        # sync at startup. This is just a heuristic for optimization, the
        # correctness of our sync algorithm does not depend on this.
        syncer = create(Syncer)
        syncer.start_later(10)
        handler = create(SocketAPIHandler)
        messagebus = create(MessageBusServer, self.listener, self.authtok, handler)
        messagebus.set_trace(self.tracefile)
        messagebus.start()
        self.messagebus = messagebus

    def _run_until_stopped(self):
        """Run the loop until the backend is notified to stop."""
        raise NotImplementedError

    def _stop_backend(self):
        """Gracefully shut down the backend components."""
        instance(MessageBusServer).stop()
        instance(Database).close()

    def main(self):
        """Run the backend main loop."""
        self.logger.debug('starting backend components')
        self._start_backend()
        self.logger.debug('starting backend event loop')
        self._run_until_stopped()
        self.logger.debug('backend event loop terminated')
        self._stop_backend()
        self.logger.debug('cleaned up backend components')

    def start(self, timeout):
        """Start the backend. This runs the main() function."""
        raise NotImplementedError

    def stop(self, timeout):
        """Stop the backend."""
        raise NotImplementedError
