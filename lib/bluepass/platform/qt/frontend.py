#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import sys
import os.path
import socket
import logging

from bluepass import _version, platform
from bluepass.factory import singleton
from bluepass.frontend import Frontend
from bluepass.backend import start_backend
from bluepass.util.optparse import OptionParserEx, OptionError
from bluepass.platform.qt.application import Bluepass
from bluepass.platform.qt.messagebus import QtMessageBusConnection, QtMessageBusHandler
from bluepass.platform.qt.backend import BackendProxy


def todict(obj):
    """Convert an object with attribues to a dictionary."""
    return dict(((key, getattr(obj, key)) for key in dir(obj)
                 if not key.startswith('_')))


class QtFrontend(Frontend):
    """Qt frontend for Bluepass."""

    name = 'Qt'

    def __init__(self):
        """Constructor."""
        super(QtFrontend, self).__init__()
        self.appdir = platform.get_appdir('bluepass')

    def parse_args(self, args):
        """Parse command-line arguments."""
        description = 'Bluepass password manager (Qt frontend). ' \
                      'See http://bluepass.org/ for more information.'
        epilog = 'In addition, any valid Qt command line option can ' \
                 'be specified.'
        parser = OptionParserEx(allow_unknown_options=True,
                                add_help_option=False,
                                description=description, epilog=epilog)
        parser.add_option('-f', '--frontend', action='store',
                          help='Select frontend to use.')
        parser.add_option('-v', '--version', action='store_true',
                          dest='show_version', help='Show version information')
        parser.add_option('-b', '--build-info', action='store_true',
                          dest='show_build_info', help='Show build information')
        parser.add_option('-r', '--data-dir', action='store',
                          dest='datadir', help='Use alternate data directory')
        parser.add_option('-d', '--debug', action='store_true',
                          help='Show debugging information')
        parser.add_option('-t', '--trace', action='store_true',
                          help='Trace socketapi exchanges [in backend.trace]')
        parser.add_option('-l', '--log-stdout', action='store_true',
                          help='Log to standard output [default: bluepass.log]')
        parser.add_option('-h', '--help', action='store_true',
                          dest='show_help', help='Show command-line help')
        self.parser = parser
        try:
            self.options, self.args = parser.parse_args(args)
        except OptionError as e:
            sys.stderr.write('Error: %s\n' % str(e))
            return False
        return True

    def show_version(self):
        """Show version information."""
        sys.stdout.write('Bluepass version %s (%s frontend)\n'
                         % (_version.version, self.name))

    def show_build_info(self):
        """Show build information (if any)."""
        if not hasattr(_version, 'build_version'):
            sys.stdout.write('No build information available\n')
            return
        sys.stdout.write('Build version: %s\n' % _version.build_version)
        sys.stdout.write('Build date: %s\n' % _version.build_date)
        sys.stdout.write('Build host: %s\n' % _version.build_host)
        sys.stdout.write('Changed files:\n')
        for change in _version.build_changes:
            sys.stdout.write('  - %s\n' % change)
        else:
            sys.stdout.write('  no files changed\n')

    def show_help(self):
        """Show help on the command-line options."""
        sys.stdout.write(self.parser.format_help())

    def setup_logging(self):
        """Configure the logging subsystem."""
        logger = logging.getLogger('bluepass')
        if self.options.log_stdout:
            handler = logging.StreamHandler(sys.stdout)
            format = 'FRONTEND %(levelname)s %(name)s'
        else:
            logname = os.path.join(self.appdir, 'bluepass.log')
            handler = logging.FileHandler(logname, 'w')
            format = '%(asctime)s %(levelname)s %(name)s'
        if self.options.debug:
            format += ' (%(filename)s:%(lineno)d)'
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.ERROR)
        format += ': %(message)s'
        handler.setFormatter(logging.Formatter(format))
        logger.addHandler(handler)
        self.logger = logger

    def start(self):
        """Start up the application."""
        options = self.options
        if options.show_help:
            self.show_help()
            return 0
        elif options.show_version:
            self.show_version()
            return 0
        elif options.show_build_info:
            self.show_build_info()
            return 0

        self.setup_logging()

        status, detail = start_backend(5, todict(options))
        if not status:
            sys.stderr.write('Could not start up backend: %s: %s\n' % (detail[1], detail[2]))
            sys.stderr.write('Try adding --debug --log-stdout for more information\n')
            return 3

        ipaddr, port, authtok = detail
        csock = socket.socket()
        csock.connect((ipaddr, port))

        app = singleton(Bluepass, self.args)
        handler = singleton(QtMessageBusHandler)
        connection = singleton(QtMessageBusConnection, csock, authtok,
                               handler=handler)
        backend = singleton(BackendProxy, connection)

        return app.exec_()
