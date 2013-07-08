#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import sys
from PyQt4.QtGui import QApplication, QIcon, QPixmap
from bluepass.factory import create, instance
from bluepass.platform.qt.backend import BackendProxy
from bluepass.platform.qt.util import iconpath
from bluepass.platform.qt.mainwindow import MainWindow
from bluepass.platform.qt.vaultmanager import VaultManager


class Bluepass(QApplication):
    """Qt application object."""

    def __init__(self, args):
        super(Bluepass, self).__init__(args)
        self._config = None
        icon = QIcon(QPixmap(iconpath('bluepass.png')))
        self.setWindowIcon(icon)

    def exec_(self):
        mainwindow = create(MainWindow)
        mainwindow.show()
        return super(Bluepass, self).exec_()

    def mainWindow(self):
        return instance(MainWindow)

    def backend(self):
        return instance(BackendProxy)

    def config(self):
        if self._config is None:
            self._config = self.backend().get_config()
        return self._config

    def update_config(self, config):
        self._config = config
        self.backend().update_config(config)
