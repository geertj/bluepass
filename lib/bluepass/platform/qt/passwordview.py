#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import math
import logging
from string import Template

from PySide.QtCore import Slot, Signal, Property, Qt, QTimer
from PySide.QtGui import (QScrollArea, QWidget, QLabel, QVBoxLayout, QPixmap,
        QHBoxLayout, QVBoxLayout, QPushButton, QLineEdit, QFrame, QIcon,
        QApplication, QTabBar, QSizePolicy, QCheckBox, QStackedWidget,
        QGridLayout, QMenu, QKeySequence)

from bluepass.ext import secmem
from bluepass.crypto import CryptoProvider
from bluepass.platform.qt.util import iconpath, SortedList
from bluepass.platform.qt.messagebus import MessageBusError
from bluepass.platform.qt.dialogs import EditPasswordDialog


def sortkey(version):
    """Return a key that established the order of items as they
    appear in our PasswordView."""
    if version['_type'] == 'Password':
        key = '%s\x00%s' % (version.get('group', 'All'),
                            version.get('name', ''))
    elif version['_type'] == 'Group':
        key = version.get('name', '')
    else:
        raise ValueError('Unknown version type: %s' % version['_type'])
    return key


def searchkey(version):
    """Return a single string that is used for matching items with
    the query entered in the search box."""
    key = '%s\000%s\000%s\000%s' % \
            (version.get('name', ''), version.get('comment', ''),
             version.get('url', ''), version.get('username', ''))
    return key.lower()


class NoVaultWidget(QFrame):
    """No Vault widget.

    This widget is shown in the PasswordView when there are no vaults yet.
    It offers a brief explanation, and buttons to create a new vault or
    connect to an existing one.
    """

    def __init__(self, parent=None):
        super(NoVaultWidget, self).__init__(parent)
        self.addWidgets()

    def addWidgets(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        layout.addSpacing(10)
        label = QLabel(self)
        label.setTextFormat(Qt.RichText)
        label.setText('<p>There are currently no vaults.</p>'
                      '<p>To store passwords in Bluepass, '
                      'you need to create a vault first.</p>')
        label.setWordWrap(True)
        layout.addWidget(label)
        layout.addSpacing(10)
        hbox = QHBoxLayout()
        layout.addLayout(hbox)
        newbtn = QPushButton('Create New Vault', self)
        newbtn.clicked.connect(self.newVault)
        hbox.addStretch(100);
        hbox.addWidget(newbtn)
        hbox.addStretch(100)
        hbox = QHBoxLayout()
        layout.addLayout(hbox)
        connectbtn = QPushButton('Connect to Existing Vault', self)
        connectbtn.clicked.connect(self.connectVault)
        hbox.addStretch(100)
        hbox.addWidget(connectbtn)
        hbox.addStretch(100)
        width = max(newbtn.sizeHint().width(),
                    connectbtn.sizeHint().width()) + 40
        newbtn.setFixedWidth(width)
        connectbtn.setFixedWidth(width)
        layout.addStretch(100)

    @Slot()
    def newVault(self):
        """Show the vault manager to create a new vault."""
        vaultmgr = QApplication.instance().mainWindow().vaultManager()
        page = vaultmgr.page('NewVaultSimplified')
        page.reset()
        page.setName('My Passwords')
        vaultmgr.showPage(page)

    @Slot()
    def connectVault(self):
        """Show the vault manager to connect to an existing vault."""
        vaultmgr = QApplication.instance().mainWindow().vaultManager()
        page = vaultmgr.page('ShowNeighborsSimplified')
        page.reset()
        vaultmgr.showPage(page)


class UnlockWidget(QFrame):
    """Unlock widget.
    
    This widget is displayed in the PasswordView when a vault is locked.
    It allows the user to enter a password to unlock the vault.
    """

    def __init__(self, vault, parent=None):
        super(UnlockWidget, self).__init__(parent)
        self.vault = vault
        self.addWidgets()
        self.loadConfig()

    def addWidgets(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        layout.addSpacing(10)
        preamble = QLabel('This vault is locked.', self)
        layout.addWidget(preamble)
        passwdedt = QLineEdit(self)
        passwdedt.setPlaceholderText('Type password to unlock')
        passwdedt.setEchoMode(QLineEdit.Password)
        passwdedt.textChanged.connect(self.passwordChanged)
        passwdedt.returnPressed.connect(self.unlockVault)
        layout.addSpacing(10)
        layout.addWidget(passwdedt)
        self.passwdedt = passwdedt
        unlockcb = QCheckBox('Try unlock other vaults too', self)
        unlockcb.stateChanged.connect(self.saveConfig)
        unlockcb.setVisible(False)
        layout.addWidget(unlockcb)
        self.unlockcb = unlockcb
        status = QLabel('', self)
        status.setVisible(False)
        status.setContentsMargins(0, 10, 0, 0)
        layout.addWidget(status)
        self.status = status
        hbox = QHBoxLayout()
        unlockbtn = QPushButton('Unlock', self)
        unlockbtn.setFixedSize(unlockbtn.sizeHint())
        unlockbtn.clicked.connect(self.unlockVault)
        unlockbtn.setEnabled(False)
        hbox.addWidget(unlockbtn)
        self.unlockbtn = unlockbtn
        hbox.addStretch(100)
        layout.addSpacing(10)
        layout.addLayout(hbox)
        layout.addStretch(100)

    def loadConfig(self):
        config = QApplication.instance().config()
        checked = config.get('Frontend', {}).get('Qt', {}). \
                get('UnlockWidget', {}).get('unlock_others', 0)
        self.unlockcb.setChecked(checked)

    @Slot()
    def saveConfig(self):
        qapp = QApplication.instance()
        config = qapp.config()
        section = config.setdefault('Frontend', {}).setdefault('Qt', {}). \
                setdefault('UnlockWidget', {})
        unlock_others = self.unlockcb.isChecked()
        section['unlock_others'] = unlock_others
        qapp.update_config(config)

    @Slot(str)
    def passwordChanged(self, password):
        self.unlockbtn.setEnabled(password != '')

    @Slot(int)
    def vaultCountChanged(self, count):
        pwview = QApplication.instance().mainWindow().passwordView()
        locked = len(pwview.lockedVaults())
        self.unlockcb.setVisible(locked > 1)

    @Slot(str)
    def setStatus(self, status):
        self.status.setText(status)
        self.status.setVisible(bool(status))

    @Slot()
    def unlockVault(self):
        qapp = QApplication.instance()
        backend = qapp.backend()
        mainwindow = qapp.mainWindow()
        password = self.passwdedt.text()
        unlock_others = self.unlockcb.isChecked()
        try:
            success = backend.unlock_vault(self.vault, password)
        except MessageBusError as e:
            status = '<i>Could not unlock vault: %s</i>' % e.error_message
            self.setStatus(status)
            return
        self.setStatus('')
        if not unlock_others:
            mainwindow.showMessage('Vault was unlocked successfully')
            return
        count = 1
        vaults = backend.get_vaults()
        for vault in vaults:
            uuid = vault['id']
            if uuid == self.vault:
                continue
            if not backend.vault_is_locked(uuid):
                continue
            try:
                backend.unlock_vault(uuid, password)
            except MessageBusError:
                pass
            else:
                count += 1
        mainwindow.showMessage('%d vaults were unlocked successfully' % count)

    @Slot()
    def reset(self):
        self.passwdedt.clear()
        qapp = QApplication.instance()
        qapp.mainWindow().loseFocus()


class NoItemWidget(QFrame):
    """No item widget.

    This widget is shown in the PasswordView when a vault has no items yet.
    It shows a small description and a button to create the first item.
    """

    def __init__(self, vault, parent=None):
        super(NoItemWidget, self).__init__(parent)
        self.vault = vault
        self.addWidgets()

    def addWidgets(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        layout.addSpacing(10)
        label = QLabel('<p>There are no passwords in this vault.</p>' \
                       '<p>Use the "+" button at the bottom of this window ' \
                       'to add a password.</p>', self)
        label.setWordWrap(True)
        layout.addWidget(label)
        layout.addStretch(100)


class GroupItem(QLabel):
    """A group heading in a list of items."""

    def __init__(self, vault, name, parent=None):
        super(GroupItem, self).__init__(name, parent)
        self.vault = vault
        self.name = name
        self.opened = True
        opener = QLabel(self)
        self.pixmap_open = QPixmap(iconpath('triangle-open.png'))
        self.pixmap_closed = QPixmap(iconpath('triangle-closed.png'))
        opener.setPixmap(self.pixmap_open)
        opener.resize(opener.pixmap().size())
        self.opener = opener
        self.setIndent(opener.width() + 12)
        self.setMargin(2)

    openStateChanged = Signal(str, str, bool)

    @Slot(int)
    def setMatchCount(self, nmatches):
        if nmatches == -1:
            self.setText(self.name)
        else:
            self.setText('%s (%d)' % (self.name, nmatches))

    def resizeEvent(self, event):
        size = self.height()
        x = (size - self.opener.width()) // 2
        y = (size - self.opener.height()) // 2 + 1
        self.opener.move(x, y)

    def mousePressEvent(self, event):
        if not self.opener.geometry().contains(event.pos()):
            return
        if self.opened:
            self.opener.setPixmap(self.pixmap_closed)
            self.opened = False
        else:
            self.opener.setPixmap(self.pixmap_open)
            self.opened = True
        self.openStateChanged.emit(self.vault, self.name, self.opened)


class PasswordItem(QWidget):

    stylesheet = """
        PasswordItem[selected="false"] QLabel#header 
                { color: palette(window-text); background-color: white; }
        PasswordItem[selected="true"] QLabel#header
                { color: palette(highlighted-text); background-color: palette(highlight); }
        #separator { color: #aaa; }
        QLabel { height: 18px; }
        QLineEdit { height: 20px; }
        QPushButton { font: normal 10px; height: 18px; }
    """
        
    def __init__(self, vault, version, parent=None):
        super(PasswordItem, self).__init__(parent)
        self.vault = vault
        self._selected = False
        self.addWidgets()
        self.setPreviewMode(False)
        self.updateData(version)

    def addWidgets(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        layout.setContentsMargins(0, 0, 0, 0)
        header = QLabel(self)
        header.setObjectName('header')
        header.setMargin(2)
        layout.addWidget(header)
        self.header = header
        detail = QFrame(self)
        self.detail = detail
        layout.addWidget(detail)
        vbox = QVBoxLayout()
        detail.setLayout(vbox)
        vbox.setContentsMargins(10, 2, 10, 2)
        grid = QGridLayout()
        grid.setColumnMinimumWidth(1, 10)
        vbox.addLayout(grid)
        label = QLabel('Username', detail)
        grid.addWidget(label, 0, 0)
        username = QLineEdit(detail)
        username.setReadOnly(True)
        grid.addWidget(username, 0, 2, 1, 2)
        self.username = username
        label = QLabel('Password', detail)
        grid.addWidget(label, 1, 0)
        password = QLineEdit(detail)
        password.setReadOnly(True)
        password.setEchoMode(QLineEdit.Password)
        grid.addWidget(password, 1, 2)
        self.password = password
        icon = QIcon(QPixmap(iconpath('eye.png')))
        button = QPushButton(icon, '', detail)
        button.setCheckable(True)
        button.toggled.connect(self.setShowPassword)
        grid.addWidget(button, 1, 3)
        hbox = QHBoxLayout()
        vbox.addLayout(hbox)
        hbox.setContentsMargins(0, 0, 0, 0)
        button = QPushButton('Copy User', detail)
        button.clicked.connect(self.copyUsernameToClipboard)
        hbox.addWidget(button)
        button = QPushButton('Copy Pwd', detail)
        button.clicked.connect(self.copyPasswordToClipboard)
        hbox.addWidget(button)
        button = QPushButton('Open / Edit', detail)
        button.clicked.connect(self.editPassword)
        hbox.addWidget(button)
        frame = QFrame(detail)
        frame.setObjectName('separator')
        frame.setFrameShape(QFrame.HLine)
        vbox.addWidget(frame)

    def getSelected(self):
        return self._selected

    def setSelected(self, selected):
        self._selected = selected

    selected = Property(bool, getSelected, setSelected)

    clicked = Signal(str, str)

    @Slot()
    def updateData(self, version):
        self.version = version
        self.header.setText(version.get('name', ''))
        self.username.setText(version.get('username', ''))
        self.password.setText(version.get('password', ''))

    @Slot(bool)
    def setPreviewMode(self, enabled):
        self.setSelected(enabled)
        self.detail.setVisible(enabled)
        # Force a recalculation based on the new value of the "selected" property.
        self.setStyleSheet(self.stylesheet)

    @Slot(bool)
    def setShowPassword(self, show):
        self.password.setEchoMode(QLineEdit.Normal if show
                                  else QLineEdit.Password)

    @Slot()
    def copyUsernameToClipboard(self):
        username = self.version.get('username', '')
        clipboard = QApplication.instance().clipboard()
        clipboard.setText(username)

    @Slot()
    def copyPasswordToClipboard(self):
        backend = QApplication.instance().backend()
        password = self.version.get('password', '')
        clipboard = QApplication.instance().clipboard()
        clipboard.setText(password)
        # Schedule a callback that will clear the clipboard. We only clear
        # it if: 1) we own the clipboard, and 2) the contents are what we
        # put on it.
        def clearClipboard():
            # There is a small race condition here where we could clear
            # somebody else's contents but there's nothing we can do about it.
            if not clipboard.ownsClipboard() or clipboard.text != password:
                return
            clipboard.clear()
        QTimer.singleShot(60000, clearClipboard)

    @Slot()
    def editPassword(self):
        pwview = QApplication.instance().mainWindow().passwordView()
        pwview.editPassword(self.vault, self.version)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.vault, self.version['id'])
        elif event.button() == Qt.RightButton:
            self.showContextMenu(event.pos())

    def showContextMenu(self, pos):
        menu = QMenu(self)
        action = menu.addAction('Copy Username')
        action.setShortcut(QKeySequence('CTRL-U'))
        action.triggered.connect(self.copyUsernameToClipboard)
        action = menu.addAction('Copy Password')
        action.setShortcut(QKeySequence('CTRL-C'))
        action.triggered.connect(self.copyPasswordToClipboard)
        menu.addSeparator()
        action = menu.addAction('Edit')
        action = menu.addAction('Delete')
        action.triggered.connect(self.deleteItem)
        menu.popup(self.mapToGlobal(pos))

    @Slot()
    def deleteItem(self):
        backend = QApplication.instance().backend()
        version = { 'id': self.version['id'], 'name': self.version['name'],
                    '_type': self.version['_type'], 'deleted': True }
        backend.delete_version(self.vault, version)


class ItemContainer(QScrollArea):
    """A container for passwords and group."""

    def __init__(self, parent=None):
        super(ItemContainer, self).__init__(parent)
        contents = QFrame(self)
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addStretch(100)
        contents.setLayout(layout)
        self.setWidget(contents)
        self.contents = contents

    def insertItem(self, pos, item):
        item.setParent(self.contents)
        self.contents.layout().insertWidget(pos, item)

    def removeItem(self, item):
        self.contents.layout().removeWidget(item)

    def resizeEvent(self, event):
        width = self.viewport().width()
        height = max(self.viewport().height(),
                     self.widget().sizeHint().height())
        self.widget().resize(width, height)

    def items(self):
        layout = self.contents.layout()
        items = [ layout.itemAt(pos).widget()
                  for pos in range(layout.count()-1) ]
        return items


class PasswordView(QWidget):
    """The main "password view" widget.

    This widget shows a tabbar and a set of ScrollArea's that show the
    contents of each vault.

    This is an "active" component in the sense that PasswordView makes
    modifications to the model directly based on the user input. It
    accesses the model via the singleton BackendProxy instance at
    QAplication.instance().backend().
    """

    stylesheet = """
        NoVaultWidget, UnlockWidget, NoItemWidget { background-color: white; border: 1px solid grey; }
        ItemContainer > QWidget > QFrame { background-color: white; border: 1px solid grey; }
        QTabBar { font: normal ${smaller}pt; }
        GroupItem { margin: 0; padding: 0; border: 0; background:
                qlineargradient(x1:0, y1:0, x2:0, y2:1, stop: 0 #ddd, stop: 1 #aaa) }
    """


    def __init__(self, parent=None):
        """Create a new password view."""
        super(PasswordView, self).__init__(parent)
        self.vaults = {}
        self.vault_order = SortedList()
        self.current_vault = None
        self.versions = {}
        self.version_order = {}
        self.current_item = {}
        self.logger = logging.getLogger(__name__)
        self.addWidgets()
        self.setStyleSheet(self.stylesheet)
        self.editpwdlg = EditPasswordDialog()
        backend = QApplication.instance().backend()
        backend.VaultAdded.connect(self.updateVault)
        backend.VaultRemoved.connect(self.updateVault)
        backend.VaultLocked.connect(self.vaultLocked)
        backend.VaultUnlocked.connect(self.vaultUnlocked)
        backend.VersionsAdded.connect(self.updateVaultItems)

    def addWidgets(self):
        """Create main layout."""
        logger = self.logger
        logger.debug('adding widgets')
        layout = QVBoxLayout()
        self.setLayout(layout)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        tabbar = QTabBar(self)
        tabbar.setFocusPolicy(Qt.NoFocus)
        tabbar.setVisible(False)
        tabbar.currentChanged.connect(self.changeVault)
        layout.addWidget(tabbar)
        self.tabbar = tabbar
        stack = QStackedWidget(self)
        layout.addWidget(stack)
        novault = NoVaultWidget(stack)
        stack.addWidget(novault)
        self.stack = stack

    def setStyleSheet(self, stylesheet):
        """Set our style sheet. Reimplemented from QWidget.setStyleSheet()
        to perform substitutions."""
        subst = {}
        qapp = QApplication.instance()
        subst['smaller'] = int(math.ceil(0.8 * qapp.font().pointSize()))
        stylesheet = Template(stylesheet).substitute(subst)
        super(PasswordView, self).setStyleSheet(stylesheet)

    def loadVaults(self):
        """Load all vaults."""
        backend = QApplication.instance().backend()
        vaults = backend.get_vaults()
        for vault in vaults:
            self.updateVault(vault)
        if self.vault_order:
            self.tabbar.setCurrentIndex(0)

    def updateVault(self, vault):
        """Update a vault, which may or may not exist already."""
        logger = self.logger
        uuid = vault['id']
        name = vault.get('name', '')
        logger.debug('updateVault() for %s (name: "%s")', uuid, name)
        deleted = vault.get('deleted', False)
        if not deleted and (uuid not in self.vaults or
                    uuid in self.vaults and
                    self.vaults[uuid].get('deleted', False)):
            logger.debug('this is a new vault')
            self.vaults[uuid] = vault
            unlocker = UnlockWidget(uuid, self.stack)
            self.vaultCountChanged.connect(unlocker.vaultCountChanged)
            self.stack.addWidget(unlocker)
            noitems = NoItemWidget(uuid, self.stack)
            self.stack.addWidget(noitems)
            items = ItemContainer(self.stack)
            self.stack.addWidget(items)
            widgets = (unlocker, noitems, items)
            pos = self.vault_order.insert(name, uuid, widgets)
            backend = QApplication.instance().backend()
            if not backend.vault_is_locked(uuid):
                logger.debug('new vault is unlocked')
                self.versions[uuid] = {}
                self.version_order[uuid] = SortedList()
                self.current_item[uuid] = None
                versions = backend.get_versions(vault['id'])
                self.updateVaultItems(uuid, versions)
            self.tabbar.insertTab(pos, name)
        elif not deleted and uuid in self.vaults and \
                self.vaults[uuid].get('name', '') != name:
            logger.debug('this vault was renamed')
            curname = self.vaults[uuid].get('name', '')
            curpos = self.vault_order.find(curname, uuid)
            assert curpos != -1
            self.vaults[uuid] = vault
            widgets = self.vault_order.dataat(curpos)
            self.vault_order.removeat(curpos)
            pos = self.vault_order.insert(name, uuid, widgets)
            self.tabbar.removeTab(curpos)
            self.tabbar.insertTab(pos, name)
        elif deleted and uuid in self.vaults and \
                not self.vaults[uuid].get('deleted', False):
            logger.debug('this vault was deleted')
            curname = self.vaults[uuid].get('name', '')
            pos = self.vault_order.find(curname, uuid)
            assert pos != -1
            self.vaults[uuid] = vault
            widgets = self.vault_order.dataat(pos)
            self.vault_order.removeat(pos)
            self.tabbar.removeTab(pos)
            for widget in widgets:
                self.stack.removeWidget(widget)
        else:
            self.vaults[uuid] = vault
        self.tabbar.setVisible(len(self.vault_order) > 1)
        self.vaultCountChanged.emit(len(self.vault_order))

    @Slot(str, list)
    def updateVaultItems(self, uuid, versions):
        """Load the versions of a vault."""
        logger = self.logger
        logger.debug('updating %d versions for vault %s', len(versions), uuid)
        assert uuid in self.vaults
        vault = self.vaults[uuid]
        name = vault.get('name', '')
        pos = self.vault_order.find(name, uuid)
        assert pos != -1
        unlocker, noitems, items = self.vault_order.dataat(pos)
        modifications = []
        current_versions = self.versions[uuid]
        current_order = self.version_order[uuid]
        # Create a list of all operations that we need to execute on the
        # layout. We sort this list on the sortkey of the item. This makes
        # the logic easier, and it will also be slightly faster (as we don't
        # need to insert items in the middle).
        for version in versions:
            vuuid = version['id']
            key = sortkey(version)
            deleted = version.get('deleted', False)
            if version['_type'] == 'Password':
                if not deleted and (vuuid not in current_versions or
                        vuuid in current_versions and \
                        current_versions[vuuid].get('deleted', False)):
                    # new, or deleted -> undeleted
                    modifications.append((key, 'new', version))
                elif not deleted and vuuid in current_versions and \
                        not current_versions[vuuid].get('deleted', False):
                    # updated
                    modifications.append((key, 'update', version))
                elif deleted and vuuid in current_versions and \
                        not current_versions[vuuid].get('deleted', False):
                    # deleted
                    modifications.append((key, 'delete', version))
            elif version['_type'] == 'Group':
                if not deleted and (vuuid not in current_versions or \
                        vuuid in current_versions and \
                        current_versions[vuuid].get('deleted', False)):
                    # new, or deleted -> undeleted
                    modifications.append((key, 'new', version))
                elif deleted and vuuid in current_versions and \
                        not current_versions[vuuid].get('deleted', False):
                    # deleted
                    modifications.append((key, 'delete', version))
        modifications.sort()
        # Now execute the operations on the layout in the order the items
        # will appear on the screen.
        for key,mod,version in modifications:
            vuuid = version['id']
            if version['_type'] == 'Password':
                if mod == 'new':
                    group = version.get('Group', 'All')
                    pos = current_order.find(group)
                    if pos == -1:
                        # No group. Don't bail on this just insert one.
                        item = GroupItem(uuid, group)
                        item.openStateChanged.connect(self.setGroupOpenState)
                        pos = current_order.insert(group, None, (item, None))
                        items.insertItem(pos, item)
                    item = PasswordItem(uuid, version)
                    item.clicked.connect(self.changeCurrentItem)
                    search = searchkey(version)
                    pos = current_order.insert(key, vuuid, (item, search))
                    items.insertItem(pos, item)
                elif mod == 'update':
                    curkey = sortkey(current_versions[vuuid])
                    curpos = current_order.find(curkey, vuuid)
                    assert curpos != -1
                    item, search = current_order.dataat(curpos)
                    item.updateData(version)
                    if key != curkey:
                        current_order.removeat(curpos)
                        newpos = current_order.insert(key, vuuid, (item, search))
                        items.removeItem(item)
                        items.insertItem(newpos, item)
                elif mod == 'delete':
                    curkey = sortkey(current_versions[vuuid])
                    curpos = current_order.find(curkey, vuuid)
                    assert curpos != -1
                    item, search = current_order.dataat(curpos)
                    current_order.removeat(curpos)
                    items.removeItem(item)
                    item.hide(); item.destroy()
                    if self.current_item[uuid] == vuuid:
                        self.current_item[uuid] = None
            elif typ == 'Group':
                if mod == 'new':
                    pos = current_order.find(key)
                    if pos == -1:
                        item = GroupItem(uuid, key)
                        item.openStateChanged.connect(self.setGroupOpenState)
                        pos = current_order.insert(key, vuuid, (item, None))
                        items.insertItem(pos, item)
                elif mod == 'delete':
                    pos = current_order.find(key)
                    # only remove the group if it is empty
                    prefix = '%s\x00' % key
                    if pos+1 == len(current_order) or \
                            not current_order.keyat(pos+1).startswith(prefix):
                        item, search = current_order.dataat(pos)
                        current_order.removeat(pos)
                        items.removeItem(item)
                        item.destroy()
        # We can now update the version cache
        for version in versions:
            current_versions[version['id']] = version
        if uuid != self.current_vault:
            return
        # Do we need to switch from the noitems -> items widget?
        if len(current_order) > 0:
            self.stack.setCurrentWidget(items)
        else:
            self.stack.setCurrentWidget(items)
            self.stack.setCurrentWidget(noitems)
        self.currentVaultItemCountChanged.emit(len(current_order))

    vaultCountChanged = Signal(int)
    currentVaultChanged = Signal(str)
    currentVaultItemCountChanged = Signal(int)

    @Slot(int)
    def changeVault(self, current):
        """Change the current vault."""
        if not self.vaults:
            return  # ignore early trigger when the slot gets connected
        if current == -1:
            self.stack.setCurrentIndex(0)
            uuid = None
        else:
            uuid = self.vault_order.valueat(current)
            unlocker, noitems, items = self.vault_order.dataat(current)
            if self.versions.get(uuid):
                self.stack.setCurrentWidget(items)
            elif uuid in self.versions:
                self.stack.setCurrentWidget(noitems)
            else:
                self.stack.setCurrentWidget(unlocker)
        self.current_vault = uuid
        self.currentVaultChanged.emit(uuid)
        nitems = len(self.version_order[uuid]) if uuid in self.versions else 0
        self.currentVaultItemCountChanged.emit(nitems)
        QApplication.instance().mainWindow().loseFocus()

    def currentVault(self):
        """Return the current vault."""
        return self.current_vault

    def lockedVaults(self):
        """Return a list of all locked vaults."""
        return [ self.vaults[uuid] for uuid in self.vault_order.itervalues()
                 if uuid not in self.versions ]

    def unlockedVaults(self):
        """Return a list of all unlocked vaults."""
        return [ self.vaults[uuid] for uuid in self.vault_order.itervalues()
                 if uuid in self.versions ]

    @Slot(dict)
    def vaultLocked(self, vault):
        """Called when a vault was locked."""
        uuid = vault['id']
        if uuid not in self.vaults:
            return
        name = vault.get('name', '')
        pos = self.vault_order.find(name, uuid)
        if pos == -1:
            return
        if uuid not in self.versions:
            return  # already locked
        unlocker, noitems, items = self.vault_order.dataat(pos)
        self.stack.setCurrentWidget(unlocker)
        for version in self.versions[uuid].itervalues():
            for key in version:
                secmem.wipe(version[key])
        del self.versions[uuid]
        del self.version_order[uuid]
        del self.current_item[uuid]
        for item in items.items():
            items.removeItem(item)
            item.hide(); item.destroy()
        self.currentVaultChanged.emit(uuid)

    @Slot(dict)
    def vaultUnlocked(self, vault):
        """Called when a vault was unlocked."""
        uuid = vault['id']
        if uuid not in self.vaults:
            return
        name = vault.get('name', '')
        pos = self.vault_order.find(name, uuid)
        if pos == -1:
            return
        if uuid in self.versions:
            return  # already unlocked
        unlocker, noitems, items = self.vault_order.dataat(pos)
        self.versions[uuid] = {}
        self.version_order[uuid] = SortedList()
        self.current_item[uuid] = None
        backend = QApplication.instance().backend()
        versions = backend.get_versions(uuid)
        self.updateVaultItems(uuid, versions)
        unlocker.reset()
        if self.current_vault and self.current_vault != uuid:
            return
        if versions:
            self.stack.setCurrentWidget(items)
            items.resizeEvent(None)
        else:
            self.stack.setCurrentWidget(noitems)
        self.parent().loseFocus()
        self.currentVaultChanged.emit(uuid)

    @Slot(str, bool)
    def setGroupOpenState(self, uuid, group, visible):
        """Open or close a group."""
        if uuid not in self.vaults:
            return
        if uuid not in self.versions:
            return  # locked
        assert uuid in self.version_order
        vault = self.vaults[uuid]
        name = vault.get('name', '')
        pos = self.vault_order.find(name, uuid)
        if pos == -1:
            return
        items = self.vault_order.dataat(pos)[2]
        current_order = self.version_order[uuid]
        vpos = current_order.find(group)
        if vpos == -1:
            return
        vpos += 1
        prefix = '%s\x00' % group
        while vpos < len(current_order) and \
                current_order.keyat(vpos).startswith(prefix):
            item = current_order.dataat(vpos)[0]
            item.setVisible(visible)
            vpos += 1
        items.resizeEvent(None)

    @Slot(str, str)
    def changeCurrentItem(self, uuid, vuuid):
        """Change the selected item."""
        if uuid not in self.vaults:
            return
        if uuid not in self.versions:
            return  # locked
        assert uuid in self.current_item
        curuuid = self.current_item[uuid]
        if vuuid == curuuid:
            return
        current_versions = self.versions[uuid]
        current_order = self.version_order[uuid]
        if curuuid is not None:
            version = current_versions[curuuid]
            key = sortkey(version)
            pos = current_order.find(key, curuuid)
            assert pos != -1
            current = current_order.dataat(pos)[0]
            current.setPreviewMode(False)
        if vuuid is not None:
            version = current_versions[vuuid]
            key = sortkey(version)
            pos = current_order.find(key, vuuid)
            assert pos != -1
            selected = current_order.dataat(pos)[0]
            selected.setPreviewMode(True)
        self.current_item[uuid] = vuuid

    @Slot(str)
    def setSearchQuery(self, query):
        """Set a search query. This shows the subset of items that match
        the query."""
        if self.current_vault is None:
            return
        uuid = self.current_vault
        assert uuid in self.vaults
        if uuid not in self.versions:
            return  # locked
        if query:
            query = query.lower()
        else:
            query = None
        current_order = self.version_order[uuid]
        group = None
        for pos,key in enumerate(current_order):
            widget, searchkey = current_order.dataat(pos)
            if '\x00' not in key:
                if group is not None:
                    group.setMatchCount(-1 if query is None else nmatches)
                group = widget
                nmatches = 0
            else:
                assert group is not None
                found = not query or searchkey.find(query) != -1
                widget.setVisible(found)
                nmatches += int(found)
        if group is not None:
            group.setMatchCount(-1 if query is None else nmatches)

    def keyPressEvent(self, event):
        """Key press event handler."""
        if event.key() == Qt.Key_Escape:
            vault = self.currentVault()
            self.changeCurrentItem(vault, None)
            self.parent().loseFocus()
        else:
            super(PasswordView, self).keyPressEvent(event)

    def hasCurrentVault(self):
        """Return whether there is a current vault."""
        return self.current_vault is not None

    def isCurrentVaultLocked(self):
        """Return whether the current vault is locked."""
        return self.current_vault not in self.versions

    def hasSelectedItem(self):
        """Return whether there's a selected item in the current vault."""
        uuid = self.current_vault
        if uuid is None:
            return False  # no vault
        if uuid not in self.versions:
            return False  # locked
        return False

    @Slot()
    def newPassword(self):
        """Show a dialog to add a password."""
        vault = self.currentVault()
        self.editpwdlg.newPassword(vault)

    @Slot(str, dict)
    def editPassword(self, vault, version):
        """Show a dialog to edit a password."""
        self.editpwdlg.editPassword(vault, version)

    @Slot()
    def newGroup(self):
        """Show a dialog to add a new group."""
        self.addgrpdlg.newGroup()
