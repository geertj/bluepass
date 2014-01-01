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
import logging

import gruvi.logging

__all__ = ['get_logger', 'setup_logging']

_default_name = 'bluepass'


def get_logger(context='', name=None):
    """Return a logger for *context*."""
    if name is None:
        name = _default_name
    return gruvi.logging.get_logger(context, name)


def set_default_logger(name):
    global _default_name
    _default_name = name


def setup_logging(options):
    """Configure logging destination."""
    logger = logging.getLogger()
    if sys.stdout.isatty() or options.log_stdout:
        handler = logging.StreamHandler(sys.stdout)
        logfmt = '%(name)s %(levelname)s %(message)s'
        handler.setFormatter(logging.Formatter(logfmt))
        logger.addHandler(handler)
    if not options.log_stdout:
        logfile = os.path.join(options.data_dir, 'bluepass.log')
        handler = logging.FileHandler(logfile, 'w')
        logfmt = '%(asctime)s %(name)s %(levelname)s %(message)s'
        handler.setFormatter(logging.Formatter(logfmt))
        logger.addHandler(handler)
    level = logging.DEBUG if options.debug else \
                logging.INFO if options.verbose else logging.WARNING
    logger.setLevel(level)
