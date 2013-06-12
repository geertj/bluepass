#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import

import optparse
from optparse import *

__all__ = optparse.__all__ + ['OptionParserEx']


class OptionParserEx(OptionParser):
    """A specialized version of OptionParser that:
    
     * Adds a "allow_unknown_options" switch to ignore unknown options.
     * Raise an OptionError instead of calling sys.exit() in case of an
       error.
    """

    def __init__(self, *args, **kwargs):
        self.allow_unknown_options = kwargs.pop('allow_unknown_options', False)
        OptionParser.__init__(self, *args, **kwargs)

    def _process_args(self, largs, rargs, values):
        if self.allow_unknown_options:
            while rargs:
                try:
                    OptionParser._process_args(self, largs, rargs, values)
                except BadOptionError as e:
                    largs.append(e.opt_str)
        else:
            OptionParser._process_args(self, largs, rargs, values)

    def error(self, msg):
        raise OptionError(msg)
