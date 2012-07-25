#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import re

_re_uuid = re.compile('^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-'
                      '[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)

def check_uuid4(s):
    return isinstance(s, (str, unicode)) and bool(_re_uuid.match(s))
