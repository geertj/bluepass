#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

from PyQt4.QtCore import Slot, Qt
from PyQt4.QtGui import (QDialog, QLineEdit, QTextEdit, QComboBox, QLabel,
        QPushButton, QHBoxLayout, QVBoxLayout, QGridLayout, QApplication,
        QIcon, QPixmap)

from bluepass.util import asset
from .util import SortedList
from .ctrlapi import ControlApiError
from .passwordbutton import GeneratePasswordButton, RandomPasswordConfiguration


class EditPasswordDialog(QDialog):
    """Add password dialog.

    This dialog allows the user to edit a password.
    """

    stylesheet = """
        QLineEdit { background-color: white; }
    """
    
    def __init__(self, parent=None):
        super(EditPasswordDialog, self).__init__(parent)
        self.vault = None
        self.version = {}
        self.fields = {}
        self.groups = {}
        self.addWidgets()
        self.setStyleSheet(self.stylesheet)
        self.resize(500, 350)

    @Slot(str, str)
    def addGroup(self, vault, name):
        if vault not in self.groups:
            self.groups[vault] = SortedList()
        group = self.groups[vault]
        pos = group.find(name)
        if pos == -1:
            group.insert(name)

    @Slot(str, str)
    def removeGroup(self, vault, name):
        if vault not in self.groups:
            return
        group = self.groups[vault]
        pos = group.find(name)
        if pos != -1:
            group.remove(name)

    def setGroup(self, group):
        pos = self.combobox.findText(group)
        if pos == -1:
            pos = 0
        self.combobox.setCurrentIndex(pos)

    def addWidgets(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        grid = QGridLayout()
        layout.addLayout(grid)
        grid.setColumnMinimumWidth(1, 20)
        grid.setColumnStretch(2, 100)
        grid.setRowStretch(6, 100)
        label = QLabel('Group', self)
        grid.addWidget(label, 0, 0)
        combobox = QComboBox(self)
        combobox.setEditable(True)
        combobox.setInsertPolicy(QComboBox.InsertAtTop)
        grid.addWidget(combobox, 0, 2)
        self.combobox = combobox
        self.fields['group'] = (combobox.currentText, None)
        label = QLabel('Name', self)
        grid.addWidget(label, 1, 0)
        nameedt = QLineEdit(self)
        nameedt.textChanged.connect(self.fieldUpdated)
        grid.addWidget(nameedt, 1, 2)
        self.nameedt = nameedt
        self.fields['name'] = (nameedt.text, nameedt.setText)
        label = QLabel('Username', self)
        grid.addWidget(label, 2, 0)
        editor = QLineEdit(self)
        grid.addWidget(editor, 2, 2)
        self.fields['username'] = (editor.text, editor.setText)
        label = QLabel('Password', self)
        grid.addWidget(label, 3, 0)
        passwdedt = QLineEdit(self)
        passwdedt.setEchoMode(QLineEdit.Password)
        passwdedt.textChanged.connect(self.fieldUpdated)
        grid.addWidget(passwdedt, 3, 2)
        self.fields['password'] = (passwdedt.text, passwdedt.setText)
        self.passwdedt = passwdedt
        config = RandomPasswordConfiguration()
        icon = QIcon(QPixmap(asset('png', 'eye.png')))
        showbtn = QPushButton(icon, '', self)
        showbtn.setCheckable(True)
        showbtn.toggled.connect(self.setShowPassword)
        showbtn.setFixedHeight(passwdedt.sizeHint().height())
        grid.addWidget(showbtn, 3, 3)
        self.showbtn = showbtn
        passwdbtn = GeneratePasswordButton('Generate', config, self)
        passwdbtn.setFixedWidth(passwdbtn.sizeHint().width())
        grid.addWidget(passwdbtn, 3, 4)
        passwdbtn.passwordGenerated.connect(passwdedt.setText)
        label = QLabel('Website')
        grid.addWidget(label, 5, 0)
        editor = QLineEdit(self)
        grid.addWidget(editor, 5, 2, 1, 3)
        self.fields['url'] = (editor.text, editor.setText)
        label = QLabel('Comment')
        grid.addWidget(label, 6, 0)
        editor = QTextEdit(self)
        editor.setAcceptRichText(False)
        grid.addWidget(editor, 6, 2, 1, 3)
        self.fields['comment'] = (editor.toPlainText, editor.setPlainText)
        layout.addStretch(100)
        hbox = QHBoxLayout()
        layout.addLayout(hbox)
        cancelbtn = QPushButton('Cancel')
        cancelbtn.clicked.connect(self.hide)
        hbox.addWidget(cancelbtn)
        savebtn = QPushButton('Save')
        savebtn.setDefault(True)
        savebtn.setEnabled(False)
        savebtn.clicked.connect(self.savePassword)
        hbox.addWidget(savebtn)
        self.savebtn = savebtn
        hbox.addStretch(100)

    @Slot()
    def fieldUpdated(self):
        name = self.nameedt.text()
        password = self.passwdedt.text()
        enabled = name != ''
        self.savebtn.setEnabled(enabled)

    @Slot(bool)
    def setShowPassword(self, show):
        if show:
            self.passwdedt.setEchoMode(QLineEdit.Normal)
        else:
            self.passwdedt.setEchoMode(QLineEdit.Password)

    @Slot(str, dict)
    def editPassword(self, vault, version):
        self.combobox.clear()
        group = version.get('group', '')
        for name in self.groups.get(vault, []):
            self.combobox.addItem(name)
        self.setGroup(group)
        for field in self.fields:
            getvalue, setvalue = self.fields[field]
            if setvalue:
                setvalue(version.get(field, ''))
        if version.get('id'):
            self.setWindowTitle('Edit Password')
            self.savebtn.setText('Save')
        else:
            self.setWindowTitle('Add Password')
            self.nameedt.setFocus()
            self.savebtn.setText('Add')
        self.vault = vault
        self.version = version
        self.show()

    @Slot()
    def savePassword(self):
        version = self.version.copy()
        for field in self.fields:
            getvalue, setvalue = self.fields[field]
            version[field] = getvalue()
        qapp = QApplication.instance()
        backend = qapp.backend()
        mainwindow = qapp.mainWindow()
        if version.get('id'):
            try:
                backend.update_version(self.vault, version)
            except ControlApiError as e:
                mainwindow.showMessage('Could not update password: %s' % str(e))
            else:
                mainwindow.showMessage('Password updated successfully')
        else:
            try:
                backend.add_version(self.vault, version)
            except ControlApiError as e:
                mainwindow.showMessage('Could not add password: %s' % str(e))
            else:
                mainwindow.showMessage('Password added successfully')
        self.hide()


class PairingApprovalDialog(QDialog):

    stylesheet = """
        QLineEdit#pinedt { font-size: 22pt; font-family: monospace; }
    """

    def __init__(self, parent=None):
        super(PairingApprovalDialog, self).__init__(parent)
        self.addWidgets()
        self.setStyleSheet(self.stylesheet)
        self.resize(400, 300)
        backend = QApplication.instance().backend()
        backend.PairingComplete.connect(self.pairingComplete)

    def addWidgets(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        preamble = QLabel(self)
        preamble.setWordWrap(True)
        layout.addWidget(preamble)
        self.preamble = preamble
        grid = QGridLayout()
        grid.setColumnMinimumWidth(1, 10)
        layout.addLayout(grid)
        namelbl = QLabel('Name', self)
        grid.addWidget(namelbl, 0, 0)
        self.namelbl = namelbl
        nameedt = QLineEdit(self)
        nameedt.setFocusPolicy(Qt.NoFocus)
        grid.addWidget(nameedt, 0, 2)
        self.nameedt = nameedt
        vaultlbl = QLabel('Vault', self)
        grid.addWidget(vaultlbl, 1, 0)
        self.vaultlbl = vaultlbl
        vaultedt = QLineEdit(self)
        vaultedt.setFocusPolicy(Qt.NoFocus)
        grid.addWidget(vaultedt, 1, 2)
        self.vaultedt = vaultedt
        hbox = QHBoxLayout(self)
        layout.addLayout(hbox)
        hbox.addStretch(100)
        pinedt = QLineEdit(self)
        pinedt.setObjectName('pinedt')
        pinedt.setFocusPolicy(Qt.NoFocus)
        hbox.addWidget(pinedt)
        self.pinedt = pinedt
        hbox.addStretch(100)
        layout.addStretch(100)
        hbox = QHBoxLayout(self)
        layout.addLayout(hbox)
        hbox.addStretch(100)
        cancelbtn = QPushButton('Deny', self)
        cancelbtn.clicked.connect(self.denyApproval)
        hbox.addWidget(cancelbtn)
        self.cancelbtn = cancelbtn
        approvebtn = QPushButton('Allow', self)
        approvebtn.clicked.connect(self.grantApproval)
        hbox.addWidget(approvebtn)
        self.approvebtn = approvebtn
        hbox.addStretch(100)

    def reset(self):
        preamble = '<p>A remote node wants to connect to one of ' \
                   'your vaults. Do you want to proceed?</p>'
        self.preamble.setText(preamble)
        self.namelbl.show()
        self.nameedt.show()
        self.vaultlbl.show()
        self.vaultedt.show()
        self.pinedt.hide()

    def getApproval(self, name, vault, pin, kxid, send_response):
        backend = QApplication.instance().backend()
        vault = backend.get_vault(vault)
        if vault is None:
            send_response(False)
            return
        self.nameedt.setText(name)
        self.vaultedt.setText(vault['name'])
        self.pinedt.setText('%s-%s' % (pin[:3], pin[3:]))
        self.kxid = kxid
        self.send_response = send_response
        self.show()

    @Slot()
    def denyApproval(self):
        self.send_response(False)
        mainwindow = QApplication.instance().mainWindow()
        mainwindow.showMessage('Denied connection request')
        self.hide()

    @Slot()
    def grantApproval(self):
        self.send_response(True)
        preamble = '<p>Enter the PIN code below in the remote device.</p>'
        self.preamble.setText(preamble)
        self.namelbl.hide()
        self.nameedt.hide()
        self.vaultlbl.hide()
        self.vaultedt.hide()
        self.pinedt.show()

    @Slot(str)
    def pairingComplete(self, kxid):
        if kxid == self.kxid:
            self.hide()
