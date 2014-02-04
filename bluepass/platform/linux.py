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

from bluepass.platform import PlatformError
from .platform_ffi import lib as _lib

__all__ = ['disable_debugging', 'lock_all_memory', 'get_process_info', 'get_peer_info']


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


processinfo = namedtuple('ProcessInfo', ('pid', 'exe', 'cmdline', 'uid', 'gid'))

def get_process_info(pid):
    """Return a ProcessInfo tuple for *pid*."""
    try:
        exe = os.readlink('/proc/{0}/exe'.format(pid))
        with open('/proc/{0}/cmdline'.format(pid)) as fin:
            cmdline = fin.readline().rstrip('\x00').split('\x00')
        uid = gid = None
        with open('/proc/{0}/status'.format(pid)) as fin:
            for line in fin:
                fields = line.split()
                if fields[0] == 'Uid:':
                    uid = int(fields[2])
                elif fields[0] == 'Gid:':
                    gid = int(fields[2])
                    break
    except OSError:
        return
    return processinfo(pid, exe, cmdline, uid, gid)


def _inet_ptox(family, addr):
    """Convert a printable IPv4 or IPv6 address into a native endian,
    hexadecimal representation."""
    n = socket.inet_pton(family, addr)
    # Need to convert 32-bit quantities from network endian (inet_pton()) to
    # native endian, and then call hexlify().
    unpacked = [struct.unpack('>I', n[i:i+4])[0] for i in range(0, len(n), 4)]
    hexlified = [binascii.hexlify(struct.pack('@I', u)) for u in unpacked]
    return b''.join(hexlified).decode('ascii').upper()

def get_peer_info(sockname, peername):
    """Return a ProcessInfo tuple for the process that is connected to the
    other end of the socket with 4-tuple (sockname, peername)."""
    if peername[0] not in ('127.0.0.1', '::1'):
        return
    # Find the socket in /proc/net/tcp[6] based on its 4-tuple
    family = socket.AF_INET if len(sockname) == 2 else socket.AF_INET6
    sock_addr = '{0}:{1:04X}'.format(_inet_ptox(family, sockname[0]), sockname[1])
    peer_addr = '{0}:{1:04X}'.format(_inet_ptox(family, peername[0]), peername[1])
    socklist = '/proc/net/{0}'.format('tcp' if family == socket.AF_INET else 'tcp6')
    with open(socklist) as fin:
        for line in fin:
            parts = line.split()
            if parts[1] == sock_addr and parts[2] == peer_addr:
                inode = parts[9]
                break
        else:
            return
    # Now find the process that is owning the socket, and return a ProcessInfo
    # tuple for it.
    for pid in os.listdir('/proc'):
        try:
            pid = int(pid)
        except ValueError:
            continue
        try:
            for fd in os.listdir('/proc/{0}/fd'.format(pid)):
                fdname = '/proc/{0}/fd/{1}'.format(pid, fd)
                try:
                    target = os.readlink(fdname)
                except OSError:
                    continue
                if target.startswith('socket:') and target[8:-1] == inode:
                    break
            else:
                continue
        except OSError as e:
            continue
        return get_process_info(pid)
