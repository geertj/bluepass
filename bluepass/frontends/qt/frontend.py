#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import sys

from bluepass import util
from bluepass.factory import singleton
from bluepass.component import Component

from .application import Bluepass
from .socketapi import QtSocketApiClient


class QtFrontend(Component):
    """Qt frontend for Bluepass."""

    name = 'qt'
    description = 'GUI frontend based on Qt and PyQt4'

    @classmethod
    def add_options(cls, parser):
        """Add command-line arguments."""
        group = parser.add_argument_group('Options for Qt frontend')
        group.add_argument('--qt-options', metavar='OPTIONS', default='',
                           help='Comma-separated list of Qt internal options')

    def run(self):
        """Start up the application."""
        args = [sys.argv[0]]
        qt_options = self.options.qt_options
        args += map(lambda o: '-{0}'.format(o.strip()), qt_options.split(','))
        app = singleton(Bluepass, args)

        addr = util.paddr(self.options.connect)
        socketapi = singleton(QtSocketApiClient)
        socketapi.connect(addr)

        return app.exec_()
