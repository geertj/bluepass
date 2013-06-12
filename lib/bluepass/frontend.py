#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.


class Frontend(object):
    """Base class for Bluepass frontends."""

    name = None

    def parse_args(self, argv):
        return True

    def start(self):
        raise NotImplementedError
