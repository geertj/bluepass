#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import time
import socket

from PyQt4.QtCore import QObject, QProcess, Signal

from bluepass import util
from bluepass.backend import BackendController


class QtBackendController(BackendController):

    def __init__(self, options):
        super(QtBackendController, self).__init__(options)
        self.process = None

    def start(self):
        if self.process is not None:
            raise RuntimeError('Backend was already started')
        executable, args, env = self.startup_info()
        proc = self.process = QProcess()
        proc.setProcessChannelMode(QProcess.ForwardedChannels)
        env = ['{}={}'.format(k, v) for (k,v) in env.items()]
        proc.setEnvironment(env)
        proc.start(executable, args[1:])
        proc.waitForStarted()

    def stop(self):
        if self.process is None:
            raise RuntimeError('Backend is not running')
        proc = self.process
        now = time.time()
        end_time = now + self.timeout
        while True:
            proc.terminate()
            time.sleep(0.1)
            if proc.state() == QProcess.NotRunning:
                break
            now = time.time()
            if now > end_time:
                break
        if proc.state() != QProcess.NotRunning:
            proc.kill()
            time.sleep(0.1)
        self.process = None

    def connect(self):
        sock = None
        now = time.time()
        end_time = now + self.timeout
        while True:
            addrspec = self.backend_address()
            if addrspec:
                addr = util.parse_address(addrspec)
                try:
                    timeout = max(0.1, (end_time-now)/2)
                    sock = util.create_connection(addr, timeout)
                except socket.error:
                    pass
                else:
                    break
            now = time.time()
            if now > end_time:
                break
            time.sleep(0.1)
        return sock
