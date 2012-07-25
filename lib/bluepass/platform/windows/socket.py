#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import errno
import socket


def socketpair(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
    """Emulate the Unix socketpair() function on Windows."""
    # We create a connected TCP socket. Note the trick with setblocking(0)
    # that prevents us from having to create a thread.
    lsock = socket.socket(family, type, proto)
    lsock.bind(('localhost', 0))
    lsock.listen(1)
    addr, port = lsock.getsockname()
    csock = socket.socket(family, type, proto)
    csock.setblocking(0)
    try:
        csock.connect((addr, port))
    except socket.error, e:
        if e.errno != errno.WSAEWOULDBLOCK:
            raise
    ssock, addr = lsock.accept()
    csock.setblocking(1)
    lsock.close()
    return (ssock, csock)

def is_interrupt(e):
    """Return whether the exception `e' is an EINTR error."""
    return e.errno == errno.EINTR

def is_woudblock(e):
    """Return whether the exception `e' is an EAGAIN error."""
    return e.errno == errno.WSAWOULDBLOCK

def is_eof(e):
    """Return whether the exception `e' is an EPIPE error."""
    return e.errno in (errno.EPIPE, errno.ECONNRESET)
