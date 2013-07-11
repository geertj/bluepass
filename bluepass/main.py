#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import sys
import logging
import argparse

from bluepass import platform
from bluepass.util import misc as util
from bluepass.factory import singleton
from bluepass.backend import Backend


def todict(obj):
    """Convert an :class:`argparse.Namespace` instance into a dictionary.

    Options that have a value of ``None`` are ignored.
    """
    d = {}
    for key in dir(obj):
        if key.startswith('_'):
            continue
        value = getattr(obj, key)
        if value is not None:
            d[key] = value
    return d


def setup_logging(options, name):
    """Set up the logging subsystem."""
    logger = logging.getLogger('bluepass')
    if options.log_stdout:
        handler = logging.StreamHandler(sys.stdout)
        format = '{} %(levelname)s %(name)s'.format(name.upper())
    else:
        logdir = options.data_dir or platform.get_appdir('bluepass')
        logname = os.path.join(logdir, '{}.log'.format(name))
        handler = logging.FileHandler(logname, 'w')
        format = '%(asctime)s %(levelname)s %(name)s'
    if options.debug:
        format += ' [%(filename)s:%(lineno)d]'
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.ERROR)
    format += ': %(message)s'
    handler.setFormatter(logging.Formatter(format))
    logger.addHandler(handler)


def frontend():
    """Frontend entry point."""

    # First get the --frontend parameter so that we can its command-line
    # options.

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-f', '--frontend', nargs='?')
    opts, _ = parser.parse_known_args()
    frontend = opts.frontend and opts.frontend[0]

    for fe in platform.get_frontends():
        if fe.name == opts.frontend or opts.frontend is None:
            Frontend = fe
            break
    else:
        sys.stderr.write('Error: no such frontend: {}'.format(opts.frontend))
        sys.stderr.write('Use --list-frontends to list available frontends')
        return 1

    # Now build the real parser and parse arguments

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--data-dir',
                        help='Use alternate data directory')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Show debugging information')
    parser.add_argument('--log-stdout', action='store_true',
                        help='Log to standard output [default: backend.log]')
    parser.add_argument('-v', '--version', action='store_true',
                        help='Show version information and exit')
    parser.add_argument('-f', '--frontend',
                        help='Select frontend to use')
    parser.add_argument('--list-frontends', action='store_true',
                        help='List available frontends and exit')

    Frontend.add_args(parser)
    Backend.add_args(parser)

    opts = parser.parse_args()

    setup_logging(opts, '{}-frontend'.format(Frontend.name))

    if opts.version:
        print('Bluepass version {}'.format(_version.verion))
        return 0

    if opts.list_frontends:
        print('Available frontends:')
        for fe in platform.get_frontends():
            print('{:-10}: {}'.format(fe.name, fe.description))
        return 0

    # Create frontend and pass control to it

    frontend = singleton(Frontend, todict(opts))
    ret = frontend.run()

    return ret


def backend():
    """Start up the backend."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--data-dir',
                        help='Use alternate data directory')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Show debugging information')
    parser.add_argument('--log-stdout', action='store_true',
                        help='Log to standard output [default: backend.log]')
    parser.add_argument('-v', '--version', action='store_true',
                        help='Show version information and exit')

    Backend.add_args(parser)
    opts = parser.parse_args()

    setup_logging(opts, 'backend')

    backend = Backend(todict(opts))
    ret = backend.run()

    return ret
