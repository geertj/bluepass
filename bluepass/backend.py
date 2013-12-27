#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import sys
import stat
import signal

import pyuv
import gruvi

from bluepass import platform, util
from bluepass.logging import *
from bluepass.factory import singleton
from bluepass.crypto import CryptoProvider
from bluepass.database import Database
from bluepass.model import Model
from bluepass.passwords import PasswordGenerator
from bluepass.locator import Locator, ZeroconfLocationSource
from bluepass.socketapi import SocketAPIServer
from bluepass.syncapi import SyncAPIServer, SyncAPIPublisher, init_syncapi_ssl
from bluepass.syncer import Syncer


class Backend(object):
    """The Bluepass backend."""

    def __init__(self, options):
        """The *options* argument must be the parsed command-line arguments."""
        self.options = options
        self.data_dir = options.get('data_dir')
        if self.data_dir is None:
            self.data_dir = platform.get_appdir('bluepass')
        self.auth_token = os.environ.get('BLUEPASS_AUTH_TOKEN')
        listen = options.get('listen')
        if listen is None:
            listen = platform.default_listen_address
        self.listen_address = util.parse_address(listen)
        self._log = get_logger(self)
        self._stop_event = gruvi.Signal()

    @classmethod
    def add_args(self, parser):
        """Add command-line arguments to *parser*.

        The *parser* must be an :py:class:`argparse.ArgumentParser` instance.
        """
        parser.add_argument('-l', '--listen',
                            help='The JSON-RPC listen address')
        parser.add_argument('--daemon', action='store_true',
                            help='Do not quit after last connection exited')
        parser.add_argument('--trace', action='store_true',
                            help='Trace JSON-RPC messages [in backend.trace]')

    def run(self):
        """Initialize the backend and run its main loop."""
        self._log.debug('initializing backend components')

        self._log.debug('initializing cryto provider')
        crypto = singleton(CryptoProvider)
        pwgen = singleton(PasswordGenerator)
        init_syncapi_ssl(self.data_dir)

        self._log.debug('initializing database')
        fname = os.path.join(self.data_dir, 'bluepass.db')
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
        socketapi.listen(self.listen_address)
        fname = os.path.join(self.data_dir, 'backend.addr')
        addr = gruvi.util.getsockname(socketapi.transport)
        addr = gruvi.util.saddr(addr)
        with open(fname, 'w') as fout:
            fout.write('{}\n'.format(addr))
        self._log.info('listening on: {}', addr)
        #socketapi._trace = self.options.get('trace')
        if not self.options.get('daemon'):
            socketapi.client_disconnected.connect(self.stop)

        self._log.debug('installing signal handlers')
        on_signal = pyuv.Signal(gruvi.get_hub().loop)
        on_signal.start(self.stop, signal.SIGTERM)

        self._log.debug('all backend components succesfully initialized')

        # This is where the backend runs (until stopped).
        self._stop_event.wait()

        self._log.debug('backend event loop terminated')

        self._log.debug('shutting down control API')
        socketapi.close()

        self._log.debug('shutting down database')
        database.close()

        self._log.debug('stopped all backend components')

    def stop(self, *ignored):
        self._stop_event.emit()


class BackendController(object):
    """Backend process controller.

    This class provide functionality to query, start and stop the status of a
    Bluepass backend.
    """

    def __init__(self, options, timeout=5):
        self.options = options
        self.timeout = timeout
        self.data_dir = options.get('data_dir')
        if self.data_dir is None:
            self.data_dir = platform.get_appdir('bluepass')

    def start(self):
        """Start up the backend."""
        raise NotImplementedError

    def stop(self):
        """Stop the backend."""
        raise NotImplementedError

    def connect(self):
        """Connect to the backend."""
        raise NotImplementedError

    def backend_address(self):
        """Return the address the backend is listening on."""
        addrname = os.path.join(self.data_dir, 'backend.addr')
        st = util.try_stat(addrname)
        if st is None:
            return None
        elif not stat.S_ISREG(st.st_mode):
            raise RuntimeError('Not a regular file: {}'.format(addrname))
        with open(addrname) as fin:
            addr = fin.readline().rstrip()
        if not addr:
            raise RuntimeError('Empty backend address')
        return addr

    def startup_info(self):
        """Return a (executable, args, env) tuple that can be used to start up
        the backend."""
        executable = sys.executable
        args = ['python', '-mbluepass.backend']
        for key in ('data_dir', 'debug', 'log_stdout', 'listen', 'trace'):
            value = self.options.get(key)
            if value is None:
                continue
            optname = '--{}'.format(key.replace('_', '-'))
            if isinstance(value, bool):
                if value:
                    args.append(optname)
            else:
                args += [optname, value]
        env = os.environ.copy()
        if 'auth_token' in self.options:
            env['BLUEPASS_AUTH_TOKEN'] = self.options['auth_token']
        return executable, args, env


# Trampoline used by BackendController to start up the backend
# without needing "bluepass-backend in $PATH.
if __name__ == '__main__':
    from bluepass import main
    sys.exit(main.backend())
