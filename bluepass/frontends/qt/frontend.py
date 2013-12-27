#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import sys
import time
import gruvi

from bluepass.factory import singleton
from bluepass.frontend import Frontend
from bluepass.util import misc as util

from .application import Bluepass
from .backend import QtBackendController
from .socketapi import QtSocketApiClient


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
            addr = gruvi.util.paddr(connect)
        else:
            bectrl = self.backend_controller = QtBackendController(self.options)
            bectrl.start()
            time.sleep(2)
            addr = gruvi.util.paddr(bectrl.backend_address())

        backend = singleton(QtSocketApiClient)
        backend.connect(addr)

        return app.exec_()
