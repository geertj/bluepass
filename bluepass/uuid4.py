#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import re
from gruvi import compat

_re_uuid = re.compile('^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-'
                      '[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)

def check(s):
    return isinstance(s, compat.string_types) and bool(_re_uuid.match(s))
