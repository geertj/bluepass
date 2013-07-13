#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import sys

from bluepass.factory import singleton
from bluepass.frontend import Frontend
from bluepass.util import misc as util
from bluepass.platform.qt.application import Bluepass
from bluepass.platform.qt.messagebus import QtMessageBusConnection, QtMessageBusHandler
from bluepass.platform.qt.backend import BackendProxy, QtBackendController


class QtFrontend(Frontend):
    """Qt frontend for Bluepass."""

    name = 'qt'
    description = 'GUI frontend based on Qt and PyQt4'

    @classmethod
    def add_args(cls, parser):
        """Add command-line arguments."""
        super(QtFrontend, cls).add_args(parser)
        group = parser.add_argument_group('Options for Qt frontend')
        group.add_argument('--qt-options',
                help='Comma-separated list of Qt internal options')

    def run(self):
        """Start up the application."""
        args = [sys.argv[0]]
        qt_options = self.options.get('qt_options', '')
        args += map(lambda s: s.strip(), qt_options.split(','))
        app = singleton(Bluepass, args)

        connect = self.options.get('connect')
        if connect:
            addr = util.parse_address(connect)
            sock = util.create_connection(addr, 5)
        else:
            bectrl = self.backend_controller = QtBackendController(self.options)
            bectrl.start()
            sock = bectrl.connect()
        if sock is None:
            sys.stderr.write('Error: could not connect to backend\n')
            return 1

        handler = singleton(QtMessageBusHandler)
        connection = singleton(QtMessageBusConnection, sock, self.auth_token,
                               handler=handler)
        backend = singleton(BackendProxy, connection)

        return app.exec_()
