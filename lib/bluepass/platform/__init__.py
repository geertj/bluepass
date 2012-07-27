#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import sys
from bluepass.error import Error


class PlatformError(Error):
    """Platform error."""


# Add your platform below:

if sys.platform in ('linux2', 'darwin'):
    from gevent import socket
    from bluepass.platform.posix import errno
    from bluepass.platform.posix.misc import *
    if sys.platform == 'linux2':
        from bluepass.platform.linux.misc import *
    elif sys.platform == 'darwin':
        from bluepass.platform.darwin.misc import *

elif sys.platform in ('win32',):
    from bluepass.platform.windows import socket

else:
    raise PlatformError('unsupported platform: %s' % sys.platform)
