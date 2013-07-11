#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from bluepass.error import Error


class KeyringError(Error):
    """Keyring error."""


class Keyring(object):
    """Interface to an OS or Desktop Environment's keyring functionality."""

    def isavailable(self):
        """Return whether the keyring is available."""
        raise NotImplementedError

    def store(self, key, password):
        """Store a password."""
        raise NotImplementedError

    def retrieve(self, key):
        """Retrieve a password."""
        raise NotImplementedError
