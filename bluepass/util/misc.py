#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import stat
import errno
import socket

import gruvi.util


def asset(*path):
    """Return the path of an asset specified by *path*."""
    dname, _ = os.path.split(__file__)
    dname, _ = os.path.split(dname)
    base = os.path.join(dname, 'assets')
    st = try_stat(base)
    if st is None or not stat.S_ISDIR(st.st_mode):
        # developer install? Try top of source dir.
        dname, _ = os.path.split(dname)
        base = os.path.join(dname, 'assets')
        st = try_stat(base)
        if st is None or not stat.S_ISDIR(st.st_mode):
            raise RuntimeError('Runtime assets not found')
    asset = os.path.join(base, *path)
    st = try_stat(asset)
    if st is None or not stat.S_ISREG(st.st_mode):
        raise RuntimeError('asset {} not found'.format('/'.join(path)))
    return asset


def gethostname():
    """Return the host name."""
    hostname = socket.gethostname()
    pos = hostname.find('.')
    if pos != -1:
        hostname = hostname[:pos]
    return hostname


def parse_address(s):
    """Parse a string form of a socket address."""
    return gruvi.util.paddr(s)


def unparse_address(address):
    """Convert a socket address into a string form."""
    return gruvi.util.saddr(address)


def create_connection(address, timeout=None):
    """Connect to *address* and return the socket object.
    
    For AF_INET/AF_INET6 socket, *address* must be a (host, port) tuple.
    For AF_UNIX sockets, it must be a string.

    This function is like ``socket.create_connection`` but also supports
    AF_UNIX.
    """
    if isinstance(address, str):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(address)
    else:
        sock = socket.create_connection(address, timeout)
    return sock


def try_stat(fname):
    """Try to stat a path. Do not raise an error if the file does not exist."""
    try:
        st = os.stat(fname)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
        st = None
    return st


def try_unlink(fname):
    """Try to unlink a path. Do not raise an error if the file does not exist."""
    try:
        os.unlink(fname)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise


def create_listener(address, backlog=10):
    """Create a listen socket bound to *address* and return it.

    For AF_INET/AF_INET6 socket, *address* must be a (host, port) tuple.
    For AF_UNIX sockets, it must be a string.
    """
    if isinstance(address, str):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try_unlink(address)
        sock.bind(address)
        # The chmod() here is just damage control. If umask is not set
        # correctly there is a race condition.
        os.chmod(address, stat.S_IRUSR|stat.S_IWUSR)
    else:
        result = socket.getaddrinfo(address[0], address[1], socket.AF_UNSPEC,
                                    socket.SOCK_STREAM)
        res = result[0]
        sock = socket.socket(*res[:3])
        sock.bind(res[4])
    sock.listen(backlog)
    return sock
