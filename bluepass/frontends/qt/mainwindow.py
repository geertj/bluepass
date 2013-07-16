#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from PyQt4.QtCore import QPoint, Qt, Slot, Signal
from PyQt4.QtGui import (QLabel, QLineEdit, QIcon, QPixmap, QPushButton,
        QAction, QMenu, QStatusBar, QKeySequence, QWidget, QFrame,
        QHBoxLayout, QVBoxLayout, QApplication, QMessageBox)

from bluepass.util.misc import asset
from .dialogs import PairingApprovalDialog
from .passwordview import VaultView
from .vaultmanager import VaultManager
from .messagebus import MessageBusError


class ClearButton(QLabel):

    def __init__(self, *args, **kwargs):
        super(ClearButton, self).__init__(*args, **kwargs)
        pixmap = QPixmap(asset('png', 'clear.png'))
        self.setPixmap(pixmap)
        self.resize(pixmap.size())
        self.setCursor(Qt.ArrowCursor)

    def mousePressEvent(self, event):
        self.parent().clear()


class SearchEditor(QLineEdit):

    def __init__(self, *args, **kwargs):
        super(SearchEditor, self).__init__(*args, **kwargs)
        self.setPlaceholderText('Enter a search term')
        icon = QLabel(self)
        pixmap = QPixmap(asset('png', 'search.png'))
        icon.setPixmap(pixmap)
        icon.resize(pixmap.size())
        self.searchicn = icon
        self.clearbtn = ClearButton(self)
        self.setTextMargins(30, 0, 30, 0)
        self.setFocusPolicy(Qt.NoFocus)
        self.current_vault = None
        self.queries = {}

    def resizeEvent(self, event):
        searchicn = self.searchicn
        searchicn.move(6, 1 + (self.height() - searchicn.height())//2)
        clearbtn = self.clearbtn
        clearbtn.move(self.width() - clearbtn.width() - 7,
                      1 + (self.height() - clearbtn.height())//2)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.parent().sink.setFocus()
            self.clear()
        else:
            super(SearchEditor, self).keyPressEvent(event)

    @Slot(str)
    def currentVaultChanged(self, uuid):
        self.queries[self.current_vault] = self.text()
        text = self.queries.get(uuid, '')
        self.setText(text)
        self.current_vault = uuid

    @Slot(int)
    def currentVaultItemCountChanged(self, count):
        if count > 0:
            self.setFocusPolicy(Qt.StrongFocus)
        else:
            self.setText('')
            self.setFocusPolicy(Qt.NoFocus)


class MenuButton(QPushButton):

    def __init__(self, parent=None):
        super(MenuButton, self).__init__(parent)
        self.setObjectName('menu')
        self.setIcon(QIcon(QPixmap(asset('png', 'bluepass-logo-48.png'))))
        self.setFocusPolicy(Qt.TabFocus)
        self.setFlat(True)
        self.buildMenu()

    def buildMenu(self):
        menu = QMenu(self)
        lockvault = menu.addAction('Lock Vault')
        lockvault.triggered.connect(self.lockVault)
        self.lockvault = lockvault
        managevaults = menu.addAction('Manage Vaults')
        managevaults.triggered.connect(self.showVaultManager)
        self.managevaults = managevaults
        visiblecb = menu.addAction('Be Visible for 60 seconds')
        visiblecb.setCheckable(True)
        visiblecb.toggled.connect(self.setAllowPairing)
        backend = QApplication.instance().backend()
        backend.AllowPairingStarted.connect(self.allowPairingStarted)
        backend.AllowPairingEnded.connect(self.allowPairingEnded)
        self.visiblecb = visiblecb
        menu.addSeparator()
        additem = menu.addAction('Add Password')
        additem.triggered.connect(self.addPassword)
        self.additem = additem
        copyuser = QAction('Copy Username', menu)
        copyuser.setShortcut(QKeySequence('CTRL+U'))
        copyuser.triggered.connect(self.copyUsername)
        menu.addAction(copyuser)
        self.copyuser = copyuser
        copypass = QAction('Copy Password', menu)
        copypass.setShortcut(QKeySequence('CTRL+C'))
        copypass.triggered.connect(self.copyPassword)
        menu.addAction(copypass)
        self.copypass = copypass
        menu.addSeparator()
        about = menu.addAction('About')
        about.triggered.connect(self.showAbout)
        self.about = about
        menu.addSeparator()
        quit = QAction('Exit', menu)
        quit.setShortcut(QKeySequence('CTRL+Q'))
        qapp = QApplication.instance()
        quit.triggered.connect(qapp.quit)
        menu.addAction(quit)
        self.setMenu(menu)

    @Slot()
    def copyUsername(self):
        qapp = QApplication.instance()
        version = qapp.mainWindow().passwordView().selectedVersion()
        username = version.get('username', '')
        qapp.copyToClipboard(username)

    @Slot()
    def copyPassword(self):
        qapp = QApplication.instance()
        version = qapp.mainWindow().passwordView().selectedVersion()
        password = version.get('password', '')
        qapp.copyToClipboard(password, 60)

    @Slot()
    def lockVault(self):
        qapp = QApplication.instance()
        mainwindow = qapp.mainWindow()
        pwview = mainwindow.passwordView()
        vault = pwview.currentVault()
        if not vault:
            return
        backend = qapp.backend()
        try:
            backend.lock_vault(vault)
        except MessageBusError as e:
            mainwindow.showMessage('Cloud not lock vault: %s' % str(e))
        else:
            mainwindow.showMessage('Vault was locked succesfully')

    @Slot()
    def addPassword(self):
        pwview = QApplication.instance().mainWindow().passwordView()
        pwview.newPassword()

    @Slot()
    def showVaultManager(self):
        mainwindow = QApplication.instance().mainWindow()
        mainwindow.showVaultManager()

    @Slot(bool)
    def setAllowPairing(self, checked):
        backend = QApplication.instance().backend()
        backend.set_allow_pairing(60 if checked else 0)
  
    @Slot(int)
    def allowPairingStarted(self, timeout):
        mainwindow = QApplication.instance().mainWindow()
        mainwindow.showMessage('Vaults will be visible for %d seconds' % timeout)

    @Slot()
    def allowPairingEnded(self):
        self.visiblecb.setChecked(False)
        mainwindow = QApplication.instance().mainWindow()
        mainwindow.showMessage('Vaults are no longer visible')

    @Slot()
    def showAbout(self):
        mainwindow = QApplication.instance().mainWindow()
        mainwindow.showAbout()

    def enableEntries(self):
        qapp = QApplication.instance()
        backend = qapp.backend()
        locatorAvailable = backend.locator_is_available()
        self.visiblecb.setEnabled(locatorAvailable)
        pwview = qapp.mainWindow().passwordView()
        versionSelected = bool(pwview.selectedVersion())
        self.copyuser.setEnabled(versionSelected)
        self.copypass.setEnabled(versionSelected)
        unlocked = not pwview.isCurrentVaultLocked()
        self.lockvault.setEnabled(unlocked)
        self.additem.setEnabled(unlocked)

    def enterEvent(self, event):
        self.setFlat(False)
        
    def leaveEvent(self, event):
        self.setFlat(True)

    def mousePressEvent(self, event):
        self.enableEntries()
        super(MenuButton, self).mousePressEvent(event)


class AddButton(QPushButton):

    def __init__(self, *args, **kwargs):
        super(AddButton, self).__init__(*args, **kwargs)
        icon = QIcon(QPixmap(asset('png', 'add.png')))
        self.setIcon(icon)
        self.clicked.connect(self.newPassword)
        self.setFlat(True)
        self.setFixedSize(30, 28)
        self.setFocusPolicy(Qt.TabFocus)
        self.setEnabled(False)

    @Slot(str)
    def currentVaultChanged(self, uuid):
        pwview = QApplication.instance().mainWindow().passwordView()
        enabled = pwview.hasCurrentVault() and not pwview.isCurrentVaultLocked()
        self.setEnabled(enabled)

    @Slot()
    def newPassword(self):
        pwview = QApplication.instance().mainWindow().passwordView()
        pwview.newPassword()

    def enterEvent(self, event):
        if self.isEnabled():
            self.setFlat(False)

    def leaveEvent(self, event):
        self.setFlat(True)


class MainWindow(QWidget):

    stylesheet = """
        QStatusBar { border: 0; }
        SearchEditor { height: 22px; background-color: white; }
        MenuButton { height: 22px; }
        MenuButton::menu-indicator { width: 0; }
        QLineEdit { height: 22px; }
    """

    def __init__(self):
        super(MainWindow, self).__init__()
        self.setObjectName('top')
        self.setWindowTitle('Bluepass')
        self.addWidgets()
        self.resize(300, 400)
        self.first = True
        self.setStyleSheet(self.stylesheet)
        self.vaultmgr = VaultManager(self)
        self.pairdlg = PairingApprovalDialog(self)

    def addWidgets(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        hbox = QHBoxLayout()
        hbox.setSpacing(4)
        hbox.setContentsMargins(8, 8, 8, 2)
        searchbox = SearchEditor()
        hbox.addWidget(searchbox)
        self.searchbox = searchbox
        menu = MenuButton(self)
        hbox.addWidget(menu)
        layout.addLayout(hbox)
        pwview = VaultView(self)
        searchbox.textChanged.connect(pwview.setSearchQuery)
        pwview.currentVaultChanged.connect(searchbox.currentVaultChanged)
        pwview.currentVaultItemCountChanged.connect(searchbox.currentVaultItemCountChanged)
        layout.addWidget(pwview)
        self.pwview = pwview
        hbox = QHBoxLayout()
        addbutton = AddButton()
        pwview.currentVaultChanged.connect(addbutton.currentVaultChanged)
        hbox.addWidget(addbutton)
        frame = QFrame()
        frame.setFrameStyle(QFrame.VLine|QFrame.Raised)
        frame.setLineWidth(1)
        frame.setFixedHeight(26)
        hbox.addWidget(frame)
        statusbar = QStatusBar()
        hbox.addWidget(statusbar)
        self.statusbar = statusbar
        self.sink = QWidget()
        self.sink.setFocusPolicy(Qt.ClickFocus)
        self.sink.resize(0, 0)
        hbox.addWidget(self.sink)
        layout.addLayout(hbox)

    @Slot()
    def connectVault(self):
        vaultmgr = QApplication.instance().mainWindow().vaultManager()
        vaultmgr.setEnableNavigation(False)
        vaultmgr.showPage('ConnectVault')

    @Slot()
    def loseFocus(self):
        self.sink.setFocus()

    def showEvent(self, event):
        if not self.first:
            return
        self.loseFocus()
        self.pwview.loadVaults()
        self.first = False

    def showMessage(self, message):
        self.statusbar.showMessage(message, 10000)

    def passwordView(self):
        return self.pwview

    def vaultManager(self):
        return self.vaultmgr

    def showAbout(self):
        backend = QApplication.instance().backend()
        version_info = backend.get_version_info()
        text = '<p><b>Bluepass password manager, version %s</b></p>' \
               '<p>Bluepass is copyright (c) 2012-2013 Geert Jansen. ' \
               'Bluepass is free software available under the GNU General ' \
               'Public License, version 3. For more  information, see ' \
               '<a href="http://bluepass.org/">http://bluepass.org/</a>.</p>' \
               % version_info['version']
        QMessageBox.about(self, 'Bluepass', text)

    def showVaultManager(self, page='ManageVaults'):
        self.vaultmgr.reset()
        self.vaultmgr.showPage(page)

    def showPairingApprovalDialog(self, name, vault, pin, kxid, send_response):
        self.pairdlg.reset()
        self.pairdlg.getApproval(name, vault, pin, kxid, send_response)
