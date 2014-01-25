#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import stat
import errno
import socket
import hashlib

from gruvi import compat
import gruvi.util


def asset(*path):
    """Return the path of an asset specified by *path*."""
    dname, _ = os.path.split(__file__)
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


def file_checksum(fname, method='sha256'):
    """Return the checksum of a file named *fname*, using the hash *method*."""
    if not hasattr(hashlib, method):
        raise ValueError('unknown method: {0}'.format(method))
    digest = getattr(hashlib, method)()
    with open(fname, 'rb') as fin:
        while True:
            block = fin.read(4096)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def gethostname():
    """Return the host name."""
    hostname = socket.gethostname()
    pos = hostname.find('.')
    if pos != -1:
        hostname = hostname[:pos]
    return hostname


def paddr(s):
    """Parse a string form of a socket address."""
    return gruvi.util.paddr(s)

def saddr(address):
    """Convert a socket address into a string form."""
    return gruvi.util.saddr(address)

def create_connection(address, timeout=None):
    """Create a connection to *address* and return the socket."""
    if isinstance(address, tuple) and ':' in address[0]:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
    elif isinstance(address, tuple) and '.' in address[0]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    elif isinstance(address, compat.string_types):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    else:
        raise ValueError('expecting IPv4/IPv6 tuple, or path')
    sock.settimeout(timeout)
    sock.connect(address)
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
    """Try to stat a path. Do not raise an error if the file does not exist."""
    try:
        st = os.unlink(fname)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
        st = None
    return st


def replace(src, dst):
    """Replace *src* with *dst*. Atomic if the Platform or Python version
    supports it."""
    if hasattr(os, 'replace'):
        os.replace(src, dst)
    elif hasattr(os, 'fork'):
        # posix has atomic rename()
        os.rename(src, dst)
    else:
        # not atomic Python <= 3.2 on Windows
        try_unlink(dst)
        os.rename(src, dst)


def write_atomic(fname, contents):
    """Atomically write *contents* to *fname* by creating a temporarily file
    and renaming it in place."""
    tmpname = '{0}-{1}.tmp'.format(fname, os.getpid())
    with open(tmpname, 'w') as fout:
        fout.write(contents)
    replace(tmpname, fname)
