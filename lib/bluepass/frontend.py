#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.


class Frontend(object):
    """Base class for Bluepass frontends."""

    name = None

    def parse_args(self, argv):
        return True

    def start(self):
        raise NotImplementedError
