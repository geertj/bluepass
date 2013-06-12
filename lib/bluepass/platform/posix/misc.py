#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import sys
import os.path
import stat
import pwd
import fcntl
import errno


def get_username(uid=None):
    """Return the current user's name."""
    if uid is None:
        try:
            return os.environ['USER']
        except KeyError:
            uid = os.getuid()
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)

def get_homedir(uid=None):
    """Return the user's home directory."""
    if uid is None:
        try:
            return os.environ['HOME']
        except KeyError:
            uid = os.getuid()
    try:
        return pwd.getpwuid(uid).pw_dir
    except KeyError:
        return None

def _try_stat(fname):
    """Stat a file name but return None in case of error."""
    try:
        return os.stat(fname)
    except OSError:
        pass

def get_appdir(appname):
    """Return a directory under $HOME to store application data."""
    candidates = []
    home = get_homedir()
    xdgdata = os.path.join(home, '.local', 'share')
    st = _try_stat(xdgdata)
    if st is not None and stat.S_ISDIR(st.st_mode):
        candidates.append(os.path.join(xdgdata, appname))
    candidates.append(os.path.join(home, '.%s' % appname))
    # See if it already exists
    for appdir in candidates:
        st = _try_stat(appdir)
        if st is not None and stat.S_ISDIR(st.st_mode):
            return appdir
    # If not create it. Just fail if someone created a non-directory
    # file system object at our desired location.
    appdir = candidates[0]
    os.mkdir(appdir)
    return appdir


class LockError(Exception):
    pass

def lock_file(lockname):
    """Create a lock file `lockname`."""
    try:
        fd = os.open(lockname, os.O_RDWR|os.O_CREAT, 0644)
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except IOError as e:
            if e.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            msg = 'lockf() failed to lock %s: %s' % (lockname, os.strerror(e.errno))
            err = LockError(msg)
            line = os.read(fd, 4096)
            lockinfo = line.rstrip().split(':')
            if len(lockinfo) == 3:
                err.lock_pid = int(lockinfo[0])
                err.lock_uid = int(lockinfo[1])
                err.lock_cmd = lockinfo[2]
            raise err
        os.ftruncate(fd, 0)
        cmd = os.path.basename(sys.argv[0])
        os.write(fd, '%d:%d:%s\n' % (os.getpid(), os.getuid(), cmd))
    except (OSError, IOError) as e:
        raise LockError('%s: %s' % (lockname, os.strerror(e.errno)))
    lock = (fd, lockname)
    return lock

def unlock_file(lock):
    """Unlock a file."""
    fd, lockname = lock
    try:
        fcntl.lockf(fd, fcntl.LOCK_UN)
        os.close(fd)
        os.unlink(lockname)
    except (OSError, IOError):
        pass
