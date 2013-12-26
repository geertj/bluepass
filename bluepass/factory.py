#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.


def instance(typ):
    """Return the singleton instance of a type."""
    if not hasattr(typ, 'instance'):
        typ.instance = typ()
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
