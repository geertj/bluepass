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
import six

import gruvi

from bluepass import platform, util, logging
from .factory import *
from .component import Component
from .store import Store
from .model import Model
from .passwords import PasswordGenerator
from .locator import Locator
from .ctrlapi import ControlApiServer
from .clientapi import ClientApiServer
from .syncapi import SyncApiServer, SyncApiPublisher
from .syncer import Syncer


def get_listen_address(options):
    """Return the default listen address."""
    if hasattr(os, 'fork'):
        addr = os.path.join(options.data_dir, 'backend.sock')
        util.try_unlink(addr)
    else:
        addr = 'localhost:0'
    return addr


class Backend(Component):
    """The Bluepass backend."""

    def __init__(self, options):
        """The *options* argument must be the parsed command-line arguments."""
        super(Backend, self).__init__(options)
        self._log = logging.get_logger(self)
        self._stop_event = gruvi.Event()
        self._process = None

    @classmethod
    def add_options(self, parser):
        """Add command-line options to *parser*."""
        group = parser.add_argument_group('Options for backend')
        group.add_argument('-l', '--listen', metavar='ADDRSPEC',
                           help='The JSON-RPC listen address (HOST:PORT or PATH)')
        group.add_argument('--trace', action='store_true',
                           help='Trace JSON-RPC messages')

    @classmethod
    def check_options(cls, options):
        """Check parsed command-line options."""
        if not options.listen:
            options.listen = get_listen_address(options)
        return True

    def run(self):
        """Initialize the backend and run its main loop."""
        if not six.PY3:
            import bluepass.ssl
            bluepass.ssl.patch_ssl_wrap_socket()

        self._log.debug('initializing backend components')

        self._log.debug('initializing password generator')
        pwgen = singleton(PasswordGenerator)

        self._log.debug('initializing document store')
        fname = os.path.join(self.options.data_dir, 'bluepass.db')
        store = singleton(Store, fname)

        self._log.debug('initializing model')
        model = singleton(Model, store)
        token = {'id': self.options.auth_token, 'expires': 0,
                 'rights': {'control_api': True}}
        model.add_token(token)

        self._log.debug('initializing locator')
        locator = singleton(Locator)
        #for ls in platform.get_location_sources():
        #    self._log.debug('adding location source: {}', ls.name)
        #    locator.add_source(ls())

        #self._log.debug('initializing sync API')
        #syncapi = singleton(SyncApiServer)
        #syncapi.listen(('0.0.0.0', 0))

        #self._log.debug('initializing sync API publisher')
        #publisher = singleton(SyncApiPublisher, syncapi)
        #publisher.start()

        if locator.sources:
            self._log.debug('initializing background sync worker')
            syncer = singleton(Syncer)
            syncer.start()
        else:
            self._log.warning('no location sources available')
            self._log.warning('network synchronization is disabled')

        self._log.debug('initializing control API')
        ctrlapi = singleton(ControlApiServer)
        if self.options.trace:
            tracename = os.path.join(self.options.data_dir, 'backend.trace')
            tracefile = open(tracename, 'w')
            ctrlapi.set_tracefile(tracefile)
        addr = gruvi.paddr(self.options.listen)
        ctrlapi.listen(addr)

        fname = os.path.join(self.options.data_dir, 'backend.run')
        addr = ctrlapi.addresses[0]
        runinfo = { 'listen': gruvi.saddr(addr), 'pid': os.getpid() }
        util.write_atomic(fname, json.dumps(runinfo))

        self._log.debug('initializing client API')
        clientapi = singleton(ClientApiServer)
        clientapi.listen()

        # This is where the backend runs (until stop_event is raised or CTRL-C
        # is pressed).
        try:
            self._stop_event.wait()
        except KeyboardInterrupt:
            self._log.info('CTRL-C pressed, exiting')

        self._log.debug('backend event loop terminated')

        self._log.debug('shutting down control API')
        ctrlapi.close()

        self._log.debug('shutting down document store')
        store.close()

        self._log.debug('stopped all backend components')

        return 0

    def stop(self):
        """Stop the backend."""
        self._stop_event.set()
