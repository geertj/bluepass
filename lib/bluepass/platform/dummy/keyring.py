#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

from bluepass.keyring import Keyring


class DummyKeyring(Keyring):
    """A dummy key ring for platforms where we don't have native keyring integration."""

    def isavailable(self):
        return False
