#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import sys

from bluepass.errors import Error

__all__ = ['PlatformError']


class PlatformError(Error):
    """Error calling a platform-specific API."""


# Unix like operating systems

if hasattr(os, 'fork'):
    from .posix import *
    if sys.platform.startswith('linux'):
        from .linux import *

    default_listen_address = os.path.join(get_appdir('bluepass'), 'bluepass.sock')

# Windows

elif sys.platform in ('win32',):
    default_listen_address = 'localhost:0'


_frontends = None

def get_frontends():
    global _frontends
    if _frontends is not None:
        return _frontends
    _frontends = []
    if hasattr(os, 'fork'):
        if sys.platform == 'darwin' or os.environ.get('DISPLAY'):
            from bluepass.frontends.qt.frontend import QtFrontend
            _frontends.append(QtFrontend)
    elif sys.platform.startswith('win'):
            from bluepass.frontends.qt.frontend import QtFrontend
            _frontends.append(QtFrontend)
    return _frontends


_location_sources = None

def get_location_sources():
    global _location_sources
    if _location_sources is not None:
        return _location_sources
    _location_sources = []
    if os.environ.get('DBUS_SESSION_BUS_ADDRESS'):
        from bluepass.platform.avahi import AvahiLocationSource
        _location_sources.append(AvahiLocationSource)
    return _location_sources
