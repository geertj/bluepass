#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import socket

def gethostname():
    """Return the host name."""
    hostname = socket.gethostname()
    pos = hostname.find('.')
    if pos != -1:
        hostname = hostname[:pos]
    return hostname
