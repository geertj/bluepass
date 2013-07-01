#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import logging

from bluepass import platform


class Frontend(object):
    """Base class for Bluepass frontends."""

    name = None
    description = None

    def __init__(self, options):
        """The *options* argument must be the parsed command-line options."""
        self.options = options
        self.data_dir = options.get('data_dir')
        if self.data_dir is None:
            self.data_dir = platform.get_appdir('bluepass')
        self.auth_token = os.environ.get('BLUEPASS_AUTH_TOKEN')
        if self.auth_token is None:
            self.auth_token = os.urandom(16).encode('hex')
        self.options['auth_token'] = self.auth_token
        self.logger = logging.getLogger('bluepass.frontend')

    @classmethod
    def add_args(cls, parser):
        """Add command-line arguments to *parser*.

        The parser must be a :py:class:`argparse.ArgumentParser` instance.
        """
        parser.add_argument('-c', '--connect',
                            help='Connect to an existing backend')

    def run(self):
        """Run the front-end.

        This method will return once the front-end has exited. The return value
        is the process exit status and should passed to :py:meth:`sys.exit`.
        """
        raise NotImplementedError
