#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import struct
import socket
import binascii
from collections import namedtuple

from bluepass.errors import *
from .platform_ffi import lib as _lib

__all__ = ['disable_debugging', 'lock_all_memory', 'get_peer_info']


def disable_debugging():
    """Disable debugging.

    Under Linux it's possible to use the ptrace() debugging API to read the
    memory of other processes with the same UID. This function disables that by
    setting the PR_SET_DUMPABLE prctl() flag to 0.
    """
    ret = _lib.prctl(_lib.PR_SET_DUMPABLE, 0, 0, 0, 0)
    if ret != 0:
        raise PlatformError('prctl() returned with error {0}'.format(ret))


def lock_all_memory():
    """Lock all memory.

    This prevents any of our memory from being swapped to disk. Note that this
    call will likely fail if CAP_IPC_LOCK is not available.
    """
    ret = _lib.mlockall(_lib.MCL_CURRENT | _lib.MCL_FUTURE)
    if ret != 0:
        raise PlatformError('mlockall() returned with error {0}'.format(ret))


peerinfo = namedtuple('PeerInfo', ('pid', 'executable', 'uid', 'gid'))

def inet_ptox(family, addr):
    """Convert a printable IPv4 or IPv6 address into a native endian,
    hexadecimal representation."""
    n = socket.inet_pton(family, addr)
    # Need to convert 32-bit quantities from network endian (inet_pton()) to
    # native endian, and then call hexlify().
    unpacked = [struct.unpack('>I', n[i:i+4])[0] for i in range(0, len(n), 4)]
    hexlified = [binascii.hexlify(struct.pack('@I', u)) for u in unpacked]
    return b''.join(hexlified).decode('ascii')

def get_peer_info(transport):
    """Verify that *transport* is indeed connected to *pid*."""
    remote = transport.getpeername()
    if remote[0] not in ('127.0.0.1', '::1'):
        return
    # Find the socket in /proc/net/tcp[6] based on its 4-tuple
    local = transport.getsockname()
    family = socket.AF_INET if len(local) == 2 else socket.AF_INET6
    local_addr = '{0}:{1:04X}'.format(inet_ptox(family, local[0]), local[1])
    remote_addr = '{0}:{1:04X}'.format(inet_ptox(family, remote[0]), remote[1])
    socklist = '/proc/net/{0}'.format('tcp' if family == socket.AF_INET else 'tcp6')
    with open(socklist) as fin:
        for line in fin:
            parts = line.split()
            if parts[1] == local_addr and parts[2] == remote_addr:
                inode = parts[9]
                break
        else:
            return
    # Now find the process that is owning the socket
    for pid in os.listdir('/proc'):
        try:
            pid = int(pid)
        except ValueError:
            continue
        try:
            for fd in os.listdir('/proc/{0}/fd'.format(pid)):
                fdname = '/proc/{0}/fd/{1}'.format(pid, fd)
                target = os.readlink(fdname)
                if target.startswith('socket:') and target[8:-1] == inode:
                    break
            else:
                continue
        except OSError:
            continue
        break
    else:
        return
    # Get the executable, UID and GID.
    executable = os.readlink('/proc/{0}/exe'.format(pid))
    with open('/proc/{0}/status'.format(pid)) as fin:
        for line in fin:
            fields = line.split()
            if fields[0] == 'Uid:':
                uid = int(fields[2])
            elif fields[0] == 'Gid:':
                gid = int(fields[2])
                break
    return peerinfo(pid, executable, uid, gid)
