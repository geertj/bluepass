#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

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
