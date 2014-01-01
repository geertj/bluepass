#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import json

import gruvi

from bluepass import platform, util, logging
from bluepass.factory import singleton
from bluepass.component import Component
from bluepass.crypto import CryptoProvider
from bluepass.database import Database
from bluepass.model import Model
from bluepass.passwords import PasswordGenerator
from bluepass.locator import Locator, ZeroconfLocationSource
from bluepass.socketapi import SocketAPIServer
from bluepass.syncapi import SyncAPIServer, SyncAPIPublisher, init_syncapi_ssl
from bluepass.syncer import Syncer


class Backend(Component):
    """The Bluepass backend."""

    def __init__(self, options):
        """The *options* argument must be the parsed command-line arguments."""
        super(Backend, self).__init__(options)
        self._log = logging.get_logger(self)
        self._stop_event = gruvi.Signal()
        self._process = None

    @classmethod
    def add_options(self, parser):
        """Add command-line options to *parser*."""
        group = parser.add_argument_group('Options for backend')
        group.add_argument('-l', '--listen', metavar='ADDRSPEC',
                           help='The JSON-RPC listen address (HOST:PORT or PATH)')
        group.add_argument('--trace', action='store_true',
                           help='Trace JSON-RPC messages (to DATA_DIR/backend.trace)')

    def run(self):
        """Initialize the backend and run its main loop."""
        self._log.debug('initializing backend components')

        self._log.debug('initializing cryto provider')
        crypto = singleton(CryptoProvider)
        pwgen = singleton(PasswordGenerator)
        init_syncapi_ssl(self.options.data_dir)

        self._log.debug('initializing database')
        fname = os.path.join(self.options.data_dir, 'bluepass.db')
        database = singleton(Database, fname)
        database.lock()

        self._log.debug('initializing model')
        model = singleton(Model, database)

        self._log.debug('initializing locator')
        locator = singleton(Locator)
        for ls in platform.get_location_sources():
            self._log.debug('adding location source: {}', ls.name)
            locator.add_source(ls())

        self._log.debug('initializing sync API')
        syncapi = singleton(SyncAPIServer)
        syncapi.listen(('0.0.0.0', 0))

        self._log.debug('initializing sync API publisher')
        publisher = singleton(SyncAPIPublisher, syncapi)
        publisher.start()

        if locator.sources:
            self._log.debug('initializing background sync worker')
            syncer = singleton(Syncer)
            syncer.start()
        else:
            self._log.warning('no location sources available')
            self._log.warning('network synchronization is disabled')

        self._log.debug('initializing control API')
        socketapi = singleton(SocketAPIServer)
        if self.options.trace:
            tracename = os.path.join(self.options.data_dir, 'backend.trace')
            tracefile = open(tracename, 'w')
            socketapi._set_tracefile(tracefile)
        addr = gruvi.util.paddr(self.options.listen)
        socketapi.listen(addr)

        fname = os.path.join(self.options.data_dir, 'backend.run')
        addr = gruvi.util.getsockname(socketapi.transport)
        runinfo = { 'listen': gruvi.util.saddr(addr), 'pid': os.getpid() }
        util.write_atomic(fname, json.dumps(runinfo))

        # This is where the backend runs (until stop_event is raised or CTRL-C
        # is pressed).
        try:
            self._stop_event.wait(timeout=None, interrupt=True)
        except KeyboardInterrupt:
            self._log.info('CTRL-C pressed, exiting')

        self._log.debug('backend event loop terminated')

        self._log.debug('shutting down control API')
        socketapi.close()

        self._log.debug('shutting down database')
        database.close()

        self._log.debug('stopped all backend components')

        return 0

    def stop(self):
        """Stop the backend."""
        self._stop_event.emit()
