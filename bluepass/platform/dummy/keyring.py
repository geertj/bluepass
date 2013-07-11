#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from bluepass.keyring import Keyring


class DummyKeyring(Keyring):
    """A dummy key ring for platforms where we don't have native keyring integration."""

    def isavailable(self):
        return False
