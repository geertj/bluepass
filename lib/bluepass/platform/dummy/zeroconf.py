#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from bluepass.zeroconf import Zeroconf

class DummyZeroconf(Zeroconf):
    """A dummy Zeroconf provider for platforms where we don't have a
    Zeroconf stack available. Note that on such platforms LAN sync will
    not work."""

    def isavailable(self):
        return False
