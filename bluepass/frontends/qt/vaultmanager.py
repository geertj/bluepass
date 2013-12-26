#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import time
import logging

from PyQt4.QtCore import Slot, Qt, QTimer, QPoint, QSize, QTimer, QEventLoop
from PyQt4.QtGui import (QWidget, QDialog, QPushButton, QHBoxLayout,
        QVBoxLayout, QStackedWidget, QTableWidget, QTableWidgetItem,
        QFrame, QHeaderView, QApplication, QGridLayout, QLineEdit,
        QLabel, QCheckBox, QMessageBox, QComboBox, QMenu, QFont,
        QFontMetrics)

Item = QTableWidgetItem

from .passwordbutton import (GeneratePasswordButton,
        DicewarePasswordConfiguration)


class Overlay(QFrame):

    stylesheet = """
        Overlay { background-color: palette(window); border: 1px solid grey; }
    """

    def __init__(self, parent=None):
        super(Overlay, self).__init__(parent)
        self.setStyleSheet(self.stylesheet)
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 10, 15, 10)
        self.setLayout(layout)
        message = QLabel(self)
        message.setWordWrap(True)
        message.setAlignment(Qt.AlignTop)
        layout.addWidget(message)
        self.message = message
        self.setStyleSheet(self.stylesheet)
        self.setWindowFlags(Qt.SplashScreen|Qt.WindowStaysOnTopHint)

    def setMessage(self, message):
        self.message.setText(message)

    def show(self):
        super(Overlay, self).show()
        self.raise_()

    def showEvent(self, event):
        parent = self.parent()
        pos = QPoint((parent.width() - self.width()) / 2,
                     (parent.height() - self.height()) / 3)
        pos = parent.mapToGlobal(pos)
        self.move(pos)
        size = self.sizeHint()
        self.resize(size.width(), max(80, size.height()))


class Page(QFrame):
    """A page in the VaultManager dialog."""

    name = 'Page'
    title = 'Description'

    def __init__(self, vaultmgr):
        super(Page, self).__init__()
        self.vaultmgr = vaultmgr
        self.defaultbtn = None
        self.oncomplete = 'hide'
        self.addPopup()

    def addPopup(self):
        popup = Overlay(self)
        popup.setFixedWidth(300)
        popup.hide()
        self.popup = popup
        autohide_timer = QTimer(self)
        autohide_timer.timeout.connect(self.hidePopup)
        self.autohide_timer = autohide_timer
        progress_timer = QTimer(self)
        progress_timer.timeout.connect(self.showProgress)
        self.progress_timer = progress_timer
        self.popup_minimum_show = 0

    def reset(self):
        """Reset the page."""
        self.hidePopup()

    def setDefaultButton(self, button):
        """Set `button` as the default button for this page."""
        self.defaultbtn = button

    def showEvent(self, event):
        # There can only be done default button in a dialog. Because we
        # multplex multiple pages with each a default button in in the
        # same dialog via a QStackedWidget, we set the right default button
        # just before the widget is shown. That will clear the other default
        # buttons and make the per-page default button the real default.
        if self.defaultbtn:
            self.defaultbtn.setDefault(True)

    def setOnCompleteAction(self, action):
        """Set what needs to happen when the vault is created.
        Possible values are "hide" and "back". """
        self.oncomplete = action

    def done(self):
        """This page is done. Execute the OnComplete action."""
        self.hidePopup()
        vaultmgr = QApplication.instance().mainWindow().vaultManager()
        if self.oncomplete == 'back':
            vaultmgr.back()
        else:
            vaultmgr.hide()

    def showPopup(self, message, minimum_show=None, autohide=None,
                  progress=None, nomove=False):
        self.message = message
        self.popup.setMessage(message)
        self.popup.show()
        if minimum_show:
            self.popup_minimum_show = time.time() + minimum_show / 1000.0
        if autohide:
            self.autohide_timer.start(autohide)
        else:
            self.autohide_timer.stop()
        if progress:
            self.progress_timer.start(progress)
        else:
            self.progress_timer.stop()

    def showProgress(self):
        self.message += '.'
        self.popup.setMessage(self.message)

    def waitPopup(self):
        if not self.popup_minimum_show:
            return
        qapp = QApplication.instance()
        while True:
            if time.time() > self.popup_minimum_show:
                break
            qapp.processEvents(QEventLoop.WaitForMoreEvents)
        self.autohide_timer.stop()
        self.progress_timer.stop()

    def hidePopup(self):
        self.waitPopup()
        self.popup.hide()

    def updatePopupPosition(self):
        if self.popup.isVisible():
            self.popup.showEvent(None)


class ManageVaults(Page):

    name = 'ManageVaults'
    title = 'Manage Vaults'

    def __init__(self, vaultmgr):
        super(ManageVaults, self).__init__(vaultmgr)
        self.addWidgets()
        self.loadVaults()

    def addWidgets(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        preamble = QLabel(self)
        layout.addWidget(preamble)
        self.preamble = preamble
        layout.addSpacing(10)
        table = QTableWidget(self)
        layout.addWidget(table)
        table.setShowGrid(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)
        table.setMinimumWidth(400)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        table.setColumnCount(4)
        table.hideColumn(0)
        table.setHorizontalHeaderLabels(['ID', 'Vault', '# of Items', '# of Peers'])
        table.setFocusPolicy(Qt.NoFocus)
        table.itemSelectionChanged.connect(self.rowSelected)
        hhead = table.horizontalHeader()
        hhead.setResizeMode(QHeaderView.Stretch)
        hhead.setHighlightSections(False)
        vhead = table.verticalHeader()
        vhead.hide()
        self.table = table
        hbox = QHBoxLayout()
        layout.addLayout(hbox)
        button = QPushButton('Create Vault', self)
        button.clicked.connect(self.createVault)
        hbox.addWidget(button)
        button = QPushButton('Connect to Vault', self)
        backend = QApplication.instance().backend()
        available = backend.locator_is_available()
        if available:
            button.clicked.connect(self.connectVault)
        else:
            button.setEnabled(False)
        hbox.addWidget(button)
        removebtn = QPushButton('Remove Vault', self)
        removebtn.setEnabled(False)
        removebtn.clicked.connect(self.removeVault)
        self.removebtn = removebtn
        hbox.addWidget(removebtn)

    def loadVaults(self):
        backend = QApplication.instance().backend()
        vaults = backend.get_vaults()
        for vault in vaults:
            self.vaultAdded(vault)
        backend.VaultAdded.connect(self.vaultAdded)
        backend.VaultRemoved.connect(self.vaultRemoved)

    def reset(self):
        preamble = 'The following vaults are present:'
        self.preamble.setText(preamble)
        self.table.clearSelection()

    @Slot()
    def rowSelected(self):
        items = self.table.selectedItems()
        self.removebtn.setEnabled(len(items) > 0)

    @Slot(dict)
    def vaultAdded(self, vault):
        table = self.table
        row = table.rowCount(); table.setRowCount(row+1)
        table.setItem(row, 0, Item(vault['id']))
        table.setItem(row, 1, Item(vault['name']))
        backend = QApplication.instance().backend()
        stats = backend.get_vault_statistics(vault['id'])
        table.setItem(row, 2, Item(str(stats['current_versions'])))
        table.setItem(row, 3, Item(str(stats['trusted_nodes'])))
        table.sortItems(1)

    @Slot(dict)
    def vaultRemoved(self, vault):
        rows = self.table.rowCount()
        for row in range(rows):
            uuid = self.table.item(row, 0).text()
            if vault['id'] == uuid:
                self.table.removeRow(row)
                break

    @Slot()
    def createVault(self):
        vaultmgr = QApplication.instance().mainWindow().vaultManager()
        page = vaultmgr.page('NewVault')
        page.reset()
        vaultmgr.showPage(page)

    @Slot()
    def connectVault(self):
        vaultmgr = QApplication.instance().mainWindow().vaultManager()
        page = vaultmgr.page('ShowNeighbors')
        page.reset()
        vaultmgr.showPage(page)

    @Slot()
    def removeVault(self):
        row = self.table.selectedIndexes()[0].row()
        uuid = self.table.item(row, 0).text()
        text = 'Removing a vault removes all its entries.   \n' \
               'This operation cannot be undone.\n' \
               'Are you sure you want to continue?'
        result = QMessageBox.warning(self, 'Remove Vault', text,
                        QMessageBox.Ok|QMessageBox.Cancel,
                        QMessageBox.Cancel)
        if result != QMessageBox.Ok:
            return
        backend = QApplication.instance().backend()
        vault = backend.get_vault(uuid)
        backend.delete_vault(vault)


class PinEditor(QLineEdit):
    """A QLineEdit with an input mask to edit a PIN code in the
    format of 123-456.

    This could use setInputMask() but i don't like how that works
    (it works in "replace" mode and not "insert" mode).
    """

    def __init__(self, parent=None):
        super(PinEditor, self).__init__(parent)
        self.textChanged.connect(self.hyphenate)
        self.cursorPositionChanged.connect(self.updateCursor)
        self.prevtext = ''
        self.prevpos = 0
        self.nested = False

    def updateCursor(self, old, new):
        if self.nested:
            return
        self.prevpos = new

    def setTextNoSignal(self, text):
        self.nested = True
        self.setText(text)
        self.nested = False

    def hyphenate(self, text):
        if self.nested:
            return
        digits = text.replace('-', '')
        if digits and not digits.isdigit() or len(digits) > 6:
            self.setTextNoSignal(self.prevtext)
            self.setCursorPosition(self.prevpos)
            return
        pos = self.cursorPosition()
        prevpos = self.prevpos
        if len(digits) > 3:
            text = '%s-%s' % (digits[:3], digits[3:])
        else:
            text = digits
        if len(digits) == 3:
            # fully stuff with a hyphen at the end
            if pos == 3 and prevpos == 2:
                text += '-'
                pos += 1
            elif pos == 4 and prevpos >= 4:
                pos -= 1
        elif prevpos == 3 and pos == 4:
            # character inserted before '-', move over it
            pos += 1
        self.setTextNoSignal(text)
        self.setCursorPosition(pos)
        self.prevtext = text
        self.prevpos = pos

    def sizeHint(self):
        fm = QFontMetrics(self.font())
        width = fm.width('999-999') + 10
        height = fm.height() + 8
        return QSize(width, height)


class CreateVault(Page):
    """Create vault page.

    This is a multifunctional page that supports 3 related modes:

     - NewVault: create a new vault
     - NewVaultSimplified: create a new vault, simplified
     - ConnectVault: connect to an existing vault.

    """

    title = 'Create New Vault'
    stylesheet = """
        PinEditor { font-size: 22pt; font-family: monospace; }
    """

    def __init__(self, vaultmgr, name):
        super(CreateVault, self).__init__(vaultmgr)
        self.name = name
        self.method = 0
        self.uuid = None
        self.cookie = None
        self.logger = logging.getLogger(__name__)
        self.addWidgets()
        self.setStyleSheet(self.stylesheet)
        backend = QApplication.instance().backend()
        backend.VaultCreationComplete.connect(self.vaultCreationComplete)
        backend.PairNeighborStep2Completed.connect(self.pairNeighborStep2Completed)

    def addWidgets(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        preamble = QLabel()
        preamble.setWordWrap(True)
        layout.addSpacing(10)
        layout.addWidget(preamble)
        layout.addSpacing(10)
        self.preamble = preamble
        grid = QGridLayout()
        layout.addLayout(grid)
        grid.setColumnMinimumWidth(1, 20)
        grid.setColumnStretch(2, 100)
        pinlbl = QLabel('PIN', self)
        grid.addWidget(pinlbl, 0, 0)
        self.pinlbl = pinlbl
        pinedt = PinEditor(self)
        pinedt.textChanged.connect(self.fieldUpdated)
        grid.addWidget(pinedt, 0, 2)
        self.pinedt = pinedt
        namelbl = QLabel('Name', self)
        grid.addWidget(namelbl, 1, 0)
        self.namelbl = namelbl
        nameedt = QLineEdit(self)
        nameedt.textChanged.connect(self.fieldUpdated)
        grid.addWidget(nameedt, 1, 2)
        self.nameedt = nameedt
        label = QLabel('Protect with', self)
        grid.addWidget(label, 2, 0)
        methodbox = QComboBox(self)
        methodbox.addItem('Generate a secure passphrase')
        methodbox.addItem('I will enter my own passphrase')
        methodbox.addItem('Do not use a passphrase')
        grid.addWidget(methodbox, 2, 2)
        methodbox.activated.connect(self.methodUpdated)
        config = DicewarePasswordConfiguration()
        passwdbtn = GeneratePasswordButton('Generate', config, self)
        passwdbtn.setFocusPolicy(Qt.ClickFocus)
        grid.addWidget(passwdbtn, 2, 3)
        self.passwdbtn = passwdbtn
        label = QLabel('Passphrase', self)
        grid.addWidget(label, 3, 0)
        passwdedt = QLineEdit(self)
        passwdbtn.passwordGenerated.connect(passwdedt.setText)
        passwdedt.textChanged.connect(self.fieldUpdated)
        grid.addWidget(passwdedt, 3, 2, 1, 2)
        self.passwdedt = passwdedt
        repeatlbl = QLabel('Repeat', self)
        grid.addWidget(repeatlbl, 4, 0)
        self.repeatlbl = repeatlbl
        repeatedt = QLineEdit(self)
        repeatedt.setEchoMode(QLineEdit.Password)
        repeatedt.textChanged.connect(self.fieldUpdated)
        grid.addWidget(repeatedt, 4, 2, 1, 2)
        self.repeatedt = repeatedt
        unlockcb = QCheckBox('Automatically unlock when you log in', self)
        grid.addWidget(unlockcb, 5, 2, 1, 2)
        self.unlockcb = unlockcb
        status = QLabel(self)
        layout.addSpacing(10)
        layout.addWidget(status)
        self.status = status
        layout.addStretch(100)
        hbox = QHBoxLayout()
        layout.addLayout(hbox)
        cancelbtn = QPushButton('Cancel', self)
        cancelbtn.clicked.connect(self.vaultmgr.hide)
        hbox.addWidget(cancelbtn)
        self.cancelbtn = cancelbtn
        createbtn = QPushButton('Create', self)
        self.setDefaultButton(createbtn)
        createbtn.setEnabled(False)
        createbtn.clicked.connect(self.createVault)
        hbox.addWidget(createbtn)
        hbox.addStretch(100)
        self.createbtn = createbtn

    def configureMode(self, mode):
        """Configure the mode."""
        if mode == 'NewVault':
            self.title = 'Create a New Vault'
            preamble = '<p>Please enter the vault details below.</p>'
            self.pinlbl.hide()
            self.pinedt.hide()
            self.preamble.setText(preamble)
            self.nameedt.setFocus()
            self.passwdbtn.generate()
            self.setOnCompleteAction('back')
            self.cancelbtn.hide()
        elif mode == 'NewVaultSimplified':
            self.title = 'Create a New Vault'
            preamble = '<p>You are strongly recommended to protect your ' \
                       'vault with a passphrase.</p>' \
                       '<p><span style="font-weight: bold">NOTE:</span> ' \
                       'There is no way to recover a lost passphrase. ' \
                       'You may want to write down your passphrase now, ' \
                       'but you should discard of the note in a secure way ' \
                       'as soon as you have memorized it.</p>'
            self.preamble.setText(preamble)
            self.pinlbl.hide()
            self.pinedt.hide()
            self.namelbl.hide()
            self.nameedt.hide()
            self.unlockcb.hide()
            self.passwdbtn.generate()
            self.createbtn.setFocus()
            self.setOnCompleteAction('hide')
            self.cancelbtn.show()
        elif mode == 'ConnectVault':
            self.title = 'Connect to Vault'
            preamble = '<p>Please enter the PIN code that is currently ' \
                       'displayed by Bluepass on the device that you are ' \
                       'connecting to.</p>'
            self.preamble.setText(preamble)
            self.createbtn.setText('Connect')
            self.pinedt.setFocus()
            self.passwdbtn.generate()
            self.setOnCompleteAction('back')
            self.cancelbtn.hide()

    def setName(self, name):
        """Set the value for the value name."""
        self.nameedt.setText(name)

    def reset(self):
        """Reset the dialog."""
        super(CreateVault, self).reset()
        self.uuid = None
        self.cookie = None
        self.status.setText('')
        self.nameedt.setText('')
        self.pinedt.setText('')
        self.passwdedt.setText('')
        self.repeatedt.setText('')
        self.methodUpdated(0)
        self.configureMode(self.name)

    @Slot(int)
    def methodUpdated(self, method):
        """Called when the method combo box has canged value."""
        if method == 0:
            self.passwdedt.setEnabled(True)
            self.passwdedt.setEchoMode(QLineEdit.Normal)
            self.repeatlbl.hide()
            self.repeatedt.hide()
            self.passwdbtn.setEnabled(True)
            self.passwdbtn.generate()
        elif method == 1:
            self.passwdedt.setEnabled(True)
            self.passwdedt.setEchoMode(QLineEdit.Password)
            self.passwdedt.clear()
            self.passwdedt.setFocus()
            self.repeatlbl.show()
            self.repeatedt.clear()
            self.repeatedt.show()
            self.passwdbtn.setEnabled(False)
        elif method == 2:
            self.passwdedt.clear()
            self.passwdedt.setEnabled(False)
            self.passwdbtn.setEnabled(False)
            self.repeatlbl.hide()
            self.repeatedt.hide()
        self.method = method
        self.fieldUpdated()

    @Slot()
    def fieldUpdated(self):
        """Called when one of the text editors has changed content."""
        pin = self.pinedt.text()
        name = self.nameedt.text()
        password = self.passwdedt.text()
        repeat = self.repeatedt.text()
        enabled = name != ''
        if self.name == 'ConnectVault':
            enabled = enabled and len(pin) == 7
        if self.method == 0:
            enabled = enabled and password != ''
        elif self.method == 1:
            if password and repeat and repeat != password:
                self.status.setText('<i>The passphrases do not match.</i>')
            else:
                self.status.setText('')
            enabled = enabled and password != '' and password == repeat
        self.createbtn.setEnabled(enabled)

    @Slot()
    def createVault(self):
        """Create the vault in the Backend."""
        backend = QApplication.instance().backend()
        pin = self.pinedt.text().replace('-', '')
        name = self.nameedt.text()
        password = self.passwdedt.text()
        self.createbtn.setEnabled(False)
        if self.name == 'ConnectVault':
            self.showPopup('<i>Creating connection with vault </i>',
                           minimum_show=2000, progress=100)
            backend.pair_neighbor_step2(self.cookie, pin, name, password)
        else:
            self.showPopup('<i>Creating vault. This may take a few seconds.</i>',
                           minimum_show=2000, progress=100)
            self.uuid = backend.create_vault(name, password, async=True)

    @Slot(str, str, dict)
    def vaultCreationComplete(self, uuid, status, detail):
        """Signal that arrives when the asynchronous vault creation
        has completed."""
        if uuid != self.uuid:
            return
        if status == 'OK':
            if self.name == 'NewVaultSimplified':
                mainwindow = QApplication.instance().mainWindow()
                mainwindow.showMessage('The vault was successfully created.')
                self.hidePopup()
                self.vaultmgr.hide()
            else:
                self.waitPopup()
                self.hidePopup()
                page = self.vaultmgr.page('ManageVaults')
                page.showPopup('The vault was succesfully created.', autohide=2000)
                self.vaultmgr.showPage(page)
        else:
            status = '<i>Could not create vault: %s</i>' % detail.get('error_message')
            self.status.setText(status)
            self.logger.error('%s\n%s' % (detail.get('message'), detail.get('data')))
        self.createbtn.setEnabled(True)
        self.uuid = None

    @Slot(str, str, dict)
    def pairNeighborStep2Completed(self, cookie, status, detail):
        if cookie != self.cookie:
            return
        if status == 'OK':
            self.done()
        else:
            self.showPopup('<i>Error: %s</i>' % detail['data'],
                           minimum_show=2000, autohide=2000)
        self.createbtn.setEnabled(True)
        self.cookie = None


class ShowNeighbors(Page):

    name = 'ShowNeighbors'
    title = 'Connect to Existing Vault'

    def __init__(self, vaultmgr, name):
        super(ShowNeighbors, self).__init__(vaultmgr)
        self.name = name
        self.addWidgets()
        self.loadNeighbors()
        self.cookie = None
        backend = QApplication.instance().backend()
        backend.PairNeighborStep1Completed.connect(self.pairNeighborStep1Completed)

    def addWidgets(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        preamble = QLabel(self)
        preamble.setWordWrap(True)
        layout.addWidget(preamble)
        self.preamble = preamble
        layout.addSpacing(10)
        table = QTableWidget(self)
        layout.addWidget(table)
        table.setShowGrid(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)
        table.setMinimumWidth(400)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        table.setColumnCount(4)
        table.hideColumn(0)
        table.setHorizontalHeaderLabels(['ID', 'Vault', 'Source', 'On Node'])
        table.setFocusPolicy(Qt.NoFocus)
        table.itemSelectionChanged.connect(self.rowSelected)
        hhead = table.horizontalHeader()
        hhead.setResizeMode(QHeaderView.Stretch)
        hhead.setHighlightSections(False)
        vhead = table.verticalHeader(); vhead.hide()
        self.table = table
        hbox = QHBoxLayout()
        layout.addLayout(hbox)
        cancelbtn = QPushButton('Cancel', self)
        cancelbtn.clicked.connect(self.vaultmgr.hide)
        hbox.addWidget(cancelbtn)
        self.cancelbtn = cancelbtn
        connectbtn = QPushButton('Connect', self)
        connectbtn.setEnabled(False)
        connectbtn.clicked.connect(self.connectVault)
        hbox.addWidget(connectbtn)
        self.connectbtn = connectbtn
        hbox.addStretch(100)

    def configureMode(self, mode):
        if mode == 'ShowNeighbors':
            preamble = '<p>The following vault are currently available on ' \
                       'the network.</p>'
            self.preamble.setText(preamble)
            self.cancelbtn.hide()
        elif mode == 'ShowNeighborsSimplified':
            preamble = '<p>The following vaults are currently available on ' \
                       'the network.</p>' \
                       '<p><span style="font-weight: bold">NOTE:</span> ' \
                       'You must select the menu option "Be visible for ' \
                       '60 seconds" on the remove device for it to show ' \
                       'up here.</p>'
            self.preamble.setText(preamble)
            self.cancelbtn.show()

    def reset(self):
        self.cookie = None
        self.configureMode(self.name)

    def loadNeighbors(self):
        self.vaults = {}
        self.neighbors = {}
        backend = QApplication.instance().backend()
        backend.VaultAdded.connect(self.vaultAdded)
        backend.VaultRemoved.connect(self.vaultRemoved)
        vaults = backend.get_vaults()
        for vault in vaults:
            self.vaultAdded(vault)
        backend.NeighborDiscovered.connect(self.neighborUpdated)
        backend.NeighborUpdated.connect(self.neighborUpdated)
        backend.NeighborDisappeared.connect(self.neighborRemoved)
        neighbors = backend.get_neighbors()
        for neighbor in neighbors:
            self.neighborUpdated(neighbor)

    @Slot(dict)
    def vaultAdded(self, vault):
        assert vault['id'] not in self.vaults
        self.vaults[vault['id']] = vault
        for node in self.neighbors:
            neighbor = self.neighbors[node]
            # The added vault should hide any neighbor offering that vault
            if neighbor['vault'] == vault['id']:
                self.removeNeighbor(neighbor)

    @Slot(dict)
    def vaultRemoved(self, vault):
        assert vault['id'] in self.vaults
        del self.vaults[vault['id']]
        for node in self.neighbors:
            neighbor = self.neighbors[node]
            # The removed vault should show any neighbor offering that vault,
            # if that neighbor would have been visible without the vault.
            if neighbor['vault'] == vault['id'] \
                    and len(neighbor['addresses']) > 0 \
                    and neighbor['properties'].get('visible') == 'true':
                self.updateNeighbor(neighbor)

    @Slot(dict)
    def neighborUpdated(self, neighbor):
        self.neighbors[neighbor['node']] = neighbor
        if len(neighbor['addresses']) > 0 \
                and neighbor['properties'].get('visible') == 'true' \
                and neighbor['vault'] not in self.vaults:
            self.updateNeighbor(neighbor)
        else:
            self.removeNeighbor(neighbor)

    @Slot(dict)
    def neighborRemoved(self, neighbor):
        assert neighbor['node'] in self.neighbors
        del self.neighbors[neighbor['node']]
        self.removeNeighbor(neighbor)

    def updateNeighbor(self, neighbor):
        table = self.table
        for row in range(table.rowCount()):
            node = table.item(row, 0).text()
            source = table.item(row, 2).text()
            if neighbor['node'] == node and neighbor['source'] == source:
                table.setItem(row, 1, Item(neighbor['vaultname']))
                table.setItem(row, 3, Item(neighbor['nodename']))
                break
        else:
            row = table.rowCount()
            table.setRowCount(row+1)
            table.setItem(row, 0, Item(neighbor['node']))
            table.setItem(row, 1, Item(neighbor['vaultname']))
            table.setItem(row, 2, Item(neighbor['source']))
            table.setItem(row, 3, Item(neighbor['nodename']))
            table.sortItems(1)

    def removeNeighbor(self, neighbor):
        table = self.table
        for row in range(table.rowCount()):
            node = table.item(row, 0).text()
            source = table.item(row, 2).text()
            if neighbor['node'] == node and neighbor['source'] == source:
                table.removeRow(row)
                break

    @Slot()
    def rowSelected(self):
        items = self.table.selectedItems()
        self.connectbtn.setEnabled(len(items) > 0)

    @Slot()
    def connectVault(self):
        backend = QApplication.instance().backend()
        self.showPopup('<i>Requesting approval to connnect</i><br>',
                       progress=500)
        self.connectbtn.setEnabled(False)
        items = self.table.selectedIndexes()
        row = items[0].row()
        node = self.table.item(row, 0).text()
        vault = self.table.item(row, 1).text()
        source = self.table.item(row, 2).text()
        self.cookie = backend.pair_neighbor_step1(node, source)
        self.vault = vault

    @Slot(str, str, dict)
    def pairNeighborStep1Completed(self, cookie, status, detail):
        if cookie != self.cookie:
            return
        if status == 'OK':
            self.hidePopup()
            vaultmgr = QApplication.instance().mainWindow().vaultManager()
            page = vaultmgr.page('ConnectVault')
            page.reset()
            page.setName(self.vault)
            page.cookie = cookie
            vaultmgr.showPage(page)
        else:
            self.showPopup('<i>Error: %s</i>' % detail['data'],
                           minimum_show=2000, autohide=2000)
            self.hidePopup()
        self.connectbtn.setEnabled(True)


class VaultManager(QDialog):
    """The Vault Manager.

    This is a modeless top-level dialog that is used to manage vaults.

    It is an active component that makes changes to the model directly.
    """

    stylesheet = """
        QFrame#header { min-height: 30px; max-height: 30px; }
        QFrame#header QPushButton { min-height: 20px; max-height: 20px; }
        QStackedWidget > QFrame { background-color: white; border: 1px solid grey; }
    """

    def __init__(self, parent=None):
        super(VaultManager, self).__init__(parent)
        self.addWidgets()
        self.setStyleSheet(self.stylesheet)
        flags = Qt.Window|Qt.CustomizeWindowHint|Qt.WindowCloseButtonHint
        self.setWindowFlags(flags)
        self.pages = {}
        self.backlinks = {}
        self.current_page = None
        self.addPage(ManageVaults(self))
        self.addPage(CreateVault(self, 'NewVault'), back='ManageVaults')
        self.addPage(ShowNeighbors(self, 'ShowNeighbors'), back='ManageVaults')
        self.addPage(ShowNeighbors(self, 'ShowNeighborsSimplified'))
        self.addPage(CreateVault(self, 'ConnectVault'), back='ShowNeighbors')
        self.addPage(CreateVault(self, 'NewVaultSimplified'))
        self.resize(500, 400)

    def addWidgets(self):
        layout = QVBoxLayout()
        layout.setSpacing(0)
        self.setLayout(layout)
        header = QFrame(self)
        header.setObjectName('header')
        hbox = QHBoxLayout()
        hbox.addSpacing(10)
        hbox.setContentsMargins(0, 0, 0, 0)
        header.setLayout(hbox)
        backbutton = QPushButton('< Back', header)
        backbutton.clicked.connect(self.back)
        hbox.addWidget(backbutton)
        hbox.addStretch(100)
        self.backbutton = backbutton
        layout.addWidget(header)
        layout.addSpacing(5)
        self.header = header
        stack = QStackedWidget(self)
        layout.addWidget(stack)
        self.stack = stack

    def addPage(self, page, back=None):
        """Add a page."""
        index = self.stack.addWidget(page)
        self.pages[page.name] = (index, page)
        if back is not None:
            self.backlinks[page.name] = back

    def showPage(self, name):
        """Show a page."""
        if isinstance(name, Page):
            name = name.name
        if name not in self.pages:
            raise ValueError('Unknown page: %s' % name)
        index, page = self.pages[name]
        self.current_page = name
        self.stack.setCurrentIndex(index)
        self.setWindowTitle(page.title)
        self.backbutton.setVisible(name in self.backlinks)
        self.show()

    def currentPage(self):
        """Return the current page."""
        if self.current_page:
            return self.pages[self.current_page][1]

    def page(self, name):
        """Return a page."""
        if name in self.pages:
            return self.pages[name][1]

    def reset(self):
        for name in self.pages:
            self.pages[name][1].reset()
        self.showPage('ManageVaults')

    @Slot()
    def back(self):
        back = self.backlinks.get(self.current_page)
        if back is None:
            return
        self.showPage(back)

    def moveEvent(self, event):
        page = self.currentPage()
        if page:
            page.updatePopupPosition()
