#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os
import sys
import time
import signal
import errno
import select
import logging
import traceback

from gevent import monkey
from gevent.hub import get_hub
from gevent.event import Event

from bluepass.error import StructuredError
from bluepass.backend import Backend


class PosixBackend(Backend):
    """Posix Backend.

    This backed uses fork() to launch the backend in a separate process.

    The listener socket and the auth token are created in the parent and
    inherited over the fork. The startup notification uses a pipe that is
    also created in the parent and inherited over the fork.

    Terminating the backend is done by sending a SIGTERM signal.
    """

    def _signal_handler(self, signo):
        """Signal handler for SIGTERM and SIGCHLD."""
        if signo == signal.SIGTERM:
            self._stop_event.set()
        elif signo == signal.SIGCHLD:
            self._sigchld_event.set()

    def _setup_logging(self):
        """Install a new logging config so that we can redirect backend
        messages to a separate file."""
        # First remove all current handlers, so that we can install new
        # ones in the child process.
        logger = logging.getLogger()
        del logger.handlers[:]
        logger = logging.getLogger('bluepass')
        del logger.handlers[:]
        if self.options.get('log_stdout'):
            handler = logging.StreamHandler(sys.stdout)
            fmt = 'BACKEND %(levelname)s %(name)s'
        else:
            logname = os.path.join(self.datadir, 'backend.log')
            handler = logging.FileHandler(logname, 'w')
            fmt = '%(asctime)s %(levelname)s %(name)s'
        if self.options.get('debug'):
            fmt += ' (%(filename)s:%(lineno)d)'
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.ERROR)
        fmt += ': %(message)s'
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
        self.logger = logger

    def _start_backend(self):
        """Initialize the backend components. Called by Backend.main()."""
        try:
            get_hub().loop.reinit()
            self._stop_event = Event()
            event = get_hub().loop.signal(signal.SIGTERM)
            event.start(self._signal_handler, signal.SIGTERM)
            os.close(self._startup_pipe[0])
            self._setup_logging()
            super(PosixBackend, self)._start_backend()
            self.messagebus.add_callback(self._messagebus_event)
            # Make Thread.join() cooperative.
            monkey.patch_time()
        except StructuredError as e:
            status = 'ERROR:%s:%s:%s' % (e[0], e[1], e[2])
            self._set_startup_status(status)
            os._exit(1)
        except Exception as e:
            status = 'ERROR:UncaughtException:An uncaught exception occurred:%s' % str(e)
            lines = ['An uncaught exception occurred starting up the backend\n']
            lines += traceback.format_exception(*sys.exc_info())
            self.logger.error(''.join(lines))
            self._set_startup_status(status)
            os._exit(1)
        if not self._set_startup_status('OK'):
            self._stop_backend()
            os._exit(1)

    def start(self, timeout):
        """Start the backend and wait until it is initialized."""
        self._startup_pipe = os.pipe()
        pid = os.fork()
        if pid == 0:
            # child
            self.main()
            os._exit(0)
        # parent
        self.backend = pid
        self.listener.close()
        os.close(self._startup_pipe[1])
        self._sigchld_event = Event()
        event = get_hub().loop.signal(signal.SIGCHLD)
        event.start(self._signal_handler, signal.SIGCHLD)
        self.logger.debug('forked backend process, pid = %s', pid)
        self.logger.debug('waiting for it to initialize')
        status = self._get_startup_status(timeout)
        self.logger.debug('initialization status = %s', status)
        if not status:
            self.logger.debug('backend failed to start up after %d seconds', timeout)
            self.error_name = 'Timeout'
            self.error_message = 'A timeout occurred'
            self.error_detail = 'Backend failed to start up after %d seconds' % timeout
        elif status and status.startswith('ERROR:'):
            p1 = status.find(':')
            p2 = status.find(':', p1+1)
            p3 = status.find(':', p2+1)
            self.error_name = status[p1+1:p2]
            self.error_message = status[p2+1:p3]
            self.error_detail = status[p3+1:]
        return status == 'OK'

    def _messagebus_event(self, event, *args):
        """Message bus events."""
        if event == 'LastConnectionClosed':
            self.logger.debug('last connection closed, exiting')
            self._stop_event.set()

    def _run_until_stopped(self):
        """Wait until stopped."""
        self._stop_event.wait()

    def stop(self, timeout):
        """Notify the backend to stop, and wait until it has exited."""
        end = time.time() + timeout
        timeleft = timeout
        logger = self.logger
        success = True
        while True:
            try:
                logger.debug('requesting backend to stop via SIGTERM')
                os.kill(self.backend, signal.SIGTERM)
            except OSError as e:
                pass
            # The signal handler for SIGCHLD will set _sigchld_event
            self._sigchld_event.wait(1)
            self._sigchld_event.clear()
            try:
                ret = os.waitpid(self.backend, os.WNOHANG)
            except OSError as e:
                if e.errno != errno.ECHILD:
                    logger.debug('waitpid() returned %s', errno.errname(e[0]))
                    return False
                break
            if ret[0] == self.backend:
                logger.debug('backend (pid %d) exited with status %d',
                             ret[0], os.WEXITSTATUS(ret[1]))
                break
            timeleft = max(0, end - time.time())
            if timeleft == 0:
                logger.debug('backend (pid %d) did not stop after %s seconds',
                             self.backend, timeout)
                return False
        return True

    def _set_startup_status(self, status):
        """Set the startup status to `status`."""
        # This is implemented as blocking I/O on our startup pipe. It does
        # not make sense to enter the gevent event loop before the frontend
        # has received our startup status.
        logger = self.logger
        status = status[:select.PIPE_BUF]
        wfd = self._startup_pipe[1]
        while True:
            try:
                nbytes = os.write(wfd, status)
            except OSError as e:
                if e[0] == errno.EINTR:
                    continue
                errname = errno.errorcode[e[0]]
                logger.critical('write() to startup pipe returned %s', errname)
                return False
            # This is guaranteed by POSIX:
            assert nbytes == len(status)
            break
        while True:
            try:
                os.close(wfd)
            except OSError as e:
                if e[0] == errno.EINTR:
                    continue
                errname = errno.errorcode[e[0]]
                logger.critical('close() on startup pipe returned %s', errname)
                return False
            break
        return True

    def _get_startup_status(self, timeout):
        """Wait until the child has set its startup status, and return that."""
        # This is implemented as blockign I/O as it will be called from the
        # front-end where we may not have a gevent loop.
        rfd = self._startup_pipe[0]
        end = time.time() + timeout
        timeleft = timeout
        logger = self.logger
        while True:
            try:
                rfds, dummy, dummy = select.select([rfd], [], [], timeleft)
            except select.error as e:
                if e[0] == errno.EINTR:
                    timeleft = max(0, end - time.time())
                    continue
                errname = errno.errorcode[e[0]]
                logger.error('select() on startup pipe returned %s', errname)
                return ''
            if rfd not in rfds:
                return ''
            break
        while True:
            try:
                status = os.read(self._startup_pipe[0], select.PIPE_BUF)
            except OSError as e:
                if e[0] == errno.EINTR:
                    continue
                errname = errno.errorcode[e[0]]
                self.logger.error('read() on startup pipe returned %s', errname)
                return ''
            break
        while True:
            try:
                os.close(rfd)
            except OSError as e:
                if e[0] == errno.EINTR:
                    continue
                errname = errno.errorcode[e[0]]
                self.logger.error('close() on startup pipe returned %s', errname)
            break
        return status
