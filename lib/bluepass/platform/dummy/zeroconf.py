#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

from bluepass.zeroconf import Zeroconf

class DummyZeroconf(Zeroconf):
    """A dummy Zeroconf provider for platforms where we don't have a
    Zeroconf stack available. Note that on such platforms LAN sync will
    not work."""

    def isavailable(self):
        return False
