#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import sys
import stat
import pwd
import fcntl
import errno
import socket

from bluepass.platform import PlatformError


__all__ = ['get_homedir', 'get_appdir', 'lock_file', 'unlock_file']


def _try_stat(fname):
    """Stat a file name but return None in case of error."""
    try:
        return os.stat(fname)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise


def get_homedir():
    """Return the user's home directory."""
    homedir = os.environ.get('HOME')
    if not homedir:
        try:
            homedir = pwd.getpwuid(os.getuid()).pw_dir
        except KeyError:
            pass
    if not homedir:
        raise PlatformError('could not determine home directory')
    st = _try_stat(homedir)
    if st is None or not stat.S_ISDIR(st.st_mode):
        raise PlatformError('homedir does not exist or not a directory')
    return homedir


def get_appdir(appname):
    """Return a directory under $HOME to store application data."""
    candidates = []
    home = get_homedir()
    # Prefer the freedesktop XDG directory scheme, if it is implemented.
    # If not, use a traditional Unix dot directory.
    xdgdata = os.path.join(home, '.local', 'share')
    st = _try_stat(xdgdata)
    if st is not None and stat.S_ISDIR(st.st_mode):
        candidates.append(os.path.join(xdgdata, appname))
    candidates.append(os.path.join(home, '.%s' % appname))
    # Use the first candidate that exists.
    for appdir in candidates:
        st = _try_stat(appdir)
        if st is not None and stat.S_ISDIR(st.st_mode):
            return appdir
    # If no candidates exist, create the first one.
    os.mkdir(candidates[0])
    return candidates[0]


def lock_file(filename):
    """Lock the file *filename*.

    On success, an opaque object that can be passed to :meth:`unlock_file` is
    returned. On failure, an :class:`OSError` exception is raised.
    """
    # This uses the lockf() primitive. It has two major drawbacks which is that
    # it is per process (making it harder to test) and that it releases the
    # lock as soon as *any* fd referring to the file is closed (making it
    # more fragile). However it works on NFS so on balance I think I can live
    # with the drawbacks.
    # See also: http://0pointer.de/blog/projects/locking.html
    lockname = '{0}-lock'.format(filename)
    flock = open(lockname, 'a+')
    try:
        fcntl.lockf(flock.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)
    except IOError as e:
        if e.errno not in (errno.EACCES, errno.EAGAIN):
            flock.close()
            raise
        lockinfo = {}
        flock.seek(0)
        for line in flock:
            key, value = line.split(':')
            lockinfo[key.lower()] = value.strip()
        flock.close()
        pid = int(lockinfo['pid'])
        from bluepass import platform
        pinfo = platform.get_process_info(pid)
        pinfo = 'alive; cmdline={0!r}'.format(' '.join(pinfo.cmdline)) if pinfo else 'remote?'
        msg = '{0}: locked by process {1} ({2})'.format(filename, pid, pinfo)
        raise OSError(e.errno, msg)
    flock.truncate()
    flock.write('PID: {0}\n'.format(os.getpid()))
    flock.write('Command: {0}\n'.format(' '.join(sys.argv)))
    flock.write('Hostname: {0}\n'.format(socket.gethostname()))
    flock.flush()
    return flock


def unlock_file(flock):
    """Unlock a file."""
    try:
        flock.close()  # This will unlock the file.
        os.unlink(flock.name)
    except (OSError, IOError):
        pass
