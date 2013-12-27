#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import sys

from PyQt4.QtCore import QTimer
from PyQt4.QtGui import QApplication, QIcon, QPixmap

from bluepass.util.misc import asset
from bluepass.factory import singleton, instance

from .socketapi import QtSocketApiClient
from .mainwindow import MainWindow
from .vaultmanager import VaultManager


class Bluepass(QApplication):
    """Qt application object."""

    def __init__(self, args):
        super(Bluepass, self).__init__(args)
        self._config = None
        icon = QIcon(QPixmap(asset('png', 'bluepass-logo-144.png')))
        self.setWindowIcon(icon)

    def exec_(self):
        mainwindow = singleton(MainWindow)
        mainwindow.show()
        return super(Bluepass, self).exec_()

    def mainWindow(self):
        return instance(MainWindow)

    def backend(self):
        return instance(QtSocketApiClient)

    def config(self):
        if self._config is None:
            self._config = self.backend().get_config()
        return self._config

    def update_config(self, config):
        self._config = config
        self.backend().update_config(config)

    def copyToClipboard(self, text, timeout=None):
        clipboard = self.clipboard()
        clipboard.setText(text)
        if timeout is None:
            return
        def clearClipboard():
            # There is a small race condition here where we could clear
            # somebody else's contents but there's nothing we can do about it.
            if not clipboard.ownsClipboard() or clipboard.text != text:
                return
            clipboard.clear()
        QTimer.singleShot(timeout*1000, clearClipboard)
