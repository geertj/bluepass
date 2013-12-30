#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.


class Component(object):
    """Base class for Bluepass components (frontend/backend)."""

    name = None
    description = None

    def __init__(self, options):
        """The *options* argument must be the parsed command-line options."""
        self._options = options

    @property
    def options(self):
        """The parsed command-line options."""
        return self._options

    @classmethod
    def add_options(cls, parser):
        """Initialize command-line options."""

    def run(self):
        """Run the component.

        The return value is an exit status that should be passed to
        :meth:`sys.exit`.
        """
        raise NotImplementedError
