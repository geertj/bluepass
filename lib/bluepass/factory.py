#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import os
import sys
import logging

from bluepass.error import Error


class FactoryError(Error):
    """Object creation error."""


def instance(typ):
    """Return the singleton instance of a type."""
    if not hasattr(typ, 'instance'):
        raise FactoryError('instance not created yet')
    return typ.instance


def singleton(cls, *args, **kwargs):
    """Create a singleton class instance."""
    factory = kwargs.pop('factory', None)
    if factory:
        obj = factory(*args, **kwargs)
    else:
        obj = cls(*args, **kwargs)
    cls.instance = obj
    return obj


def deref(typ):
    """Dereference the singleton instance from its type."""
    if hasattr(typ, 'instance'):
        del typ.instance


def create(cls, *args, **kwargs):
    """Create a new instance of a class."""
    from bluepass.frontend import Frontend
    from bluepass.backend import Backend
    from bluepass.keyring import Keyring
    from bluepass.locator import Locator, ZeroconfLocationSource
    logger = logging.getLogger('bluepass.factory')
    if issubclass(cls, Frontend):
        name = args[0]
        if name is None:
            if sys.platform in ('linux2', 'win32', 'win64', 'darwin'):
                names = ['qt']
            else:
                raise FactoryError('Do not know what frontend to use on this plaform')
        else:
            names = [name]
        for name in names:
            try:
                if name == 'qt':
                    from bluepass.platform.qt.frontend import QtFrontend
                    cls = QtFrontend
                    break
            except ImportError:
                raise
        else:
            raise FactoryError('No front-end available')
        return singleton(cls, *args[1:], **kwargs)
    elif issubclass(cls, Backend):
        if sys.platform in ('linux2', 'darwin'):
            from bluepass.platform.posix.backend import PosixBackend
            return singleton(Backend, factory=PosixBackend, *args, **kwargs)
        elif sys.platform in ('win32', 'win64'):
            from bluepass.platform.windows.backend import WindowsBackend
            return singleton(Backend, factory=WindowsBackend, *args, **kwargs)
        else:
            raise FactoryError('Do not know what backend to use on this platform')
    elif issubclass(cls, Keyring):
        if os.environ.get('DBUS_SESSION_BUS_ADDRESS'):
            from tdbus import GEventDBusConnection, DBUS_BUS_SESSION
            from bluepass.platform.freedesktop.secrets import SecretsKeyring
            connection = GEventDBusConnection(DBUS_BUS_SESSION)
            logger.info('Using the Freedesktop secrets service as the keyring')
            return singleton(SecretsKeyring, connection)
        else:
            logger.error('No keyring available')
            return None
    elif issubclass(cls, ZeroconfLocationSource):
        if os.environ.get('DBUS_SESSION_BUS_ADDRESS'):
            from tdbus import GEventDBusConnection, DBUS_BUS_SYSTEM
            from bluepass.platform.freedesktop.avahi import AvahiLocationSource
            connection = GEventDBusConnection(DBUS_BUS_SYSTEM)
            logger.info('Using Avahi as the Zeroconf provider')
            return singleton(AvahiLocationSource, connection)
        else:
            logger.error('No zeroconf provider available')
            return None
    else:
        try:
            obj = instance(cls)
        except FactoryError:
            obj = singleton(cls, *args, **kwargs)
        return obj
