#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from PyQt4.QtCore import QTimer, Signal, Slot, Property, Qt, QPoint
from PyQt4.QtGui import (QPushButton, QStylePainter, QStyleOptionButton,
        QStyle, QGridLayout, QWidget, QLabel, QSpinBox, QLineEdit, QFrame,
        QApplication, QCheckBox, QFontMetrics)


class NoSelectSpinbox(QSpinBox):
    """This is a SpinBox that:

     * Will not select the displayed text when the value changes.
     * Does not accept keyboard input.
    """

    def __init__(self, parent=None):
        super(NoSelectSpinbox, self).__init__(parent)
        self.setFocusPolicy(Qt.NoFocus)

    def stepBy(self, amount):
        super(NoSelectSpinbox, self).stepBy(amount)
        self.lineEdit().deselect()


class StrengthIndicator(QLabel):
    """A password strength indicator.

    This is a label that gives feedback on the strength of a password.
    """

    Poor, Good, Excellent = range(3)

    stylesheet = """
        StrengthIndicator { border: 1px solid black; }
        StrengthIndicator[strength="0"] { background-color: #ff2929; }
        StrengthIndicator[strength="1"] { background-color: #4dd133; }
        StrengthIndicator[strength="2"] { background-color: #4dd133; }
    """

    def __init__(self, parent=None):
        super(StrengthIndicator, self).__init__(parent)
        self._strength = 0
        self.setStyleSheet(self.stylesheet)

    def getStrength(self):
        return self._strength
    
    def setStrength(self, strength):
        self._strength = strength
        if strength == self.Poor:
            self.setText('Poor')
        elif strength == self.Good:
            self.setText('Good')
        elif strength == self.Excellent:
            self.setText('Excellent')
        self.setStyleSheet(self.stylesheet)

    strength = Property(int, getStrength, setStrength)


class PasswordConfiguration(QFrame):
    """Base class for password configuration popups.

    A password popup is installed in a GeneratePasswordButton, and allows
    the user to customize the parameters of password generation.
    """

    def __init__(self, method, parent=None):
        super(PasswordConfiguration, self).__init__(parent)
        self.method = method
        self.parameters = []

    parametersChanged = Signal(str, list)


class DicewarePasswordConfiguration(PasswordConfiguration):
    """Configuration for Diceware password generation."""

    stylesheet = """
        PasswordConfiguration { border: 1px solid grey; }
    """

    def __init__(self, parent=None):
        super(DicewarePasswordConfiguration, self).__init__('diceware', parent)
        self.parameters = [5]
        self.addWidgets()
        self.setFixedSize(self.sizeHint())
        self.setStyleSheet(self.stylesheet)

    def addWidgets(self):
        grid = QGridLayout()
        self.setLayout(grid)
        grid.setColumnMinimumWidth(1, 10)
        label = QLabel('Length', self)
        grid.addWidget(label, 0, 0)
        spinbox = NoSelectSpinbox(self)
        spinbox.setSuffix(' words')
        spinbox.setMinimum(4)
        spinbox.setMaximum(8)
        grid.addWidget(spinbox, 0, 2)
        label = QLabel('Security', self)
        grid.addWidget(label, 1, 0)
        strength = StrengthIndicator(self)
        grid.addWidget(strength, 1, 2)
        self.strength = strength
        spinbox.valueChanged.connect(self.setParameters)
        spinbox.setValue(self.parameters[0])

    @Slot(int)
    def setParameters(self, words):
        self.parameters[0] = words
        self.updateStrength()

    @Slot()
    def updateStrength(self):
        backend = QApplication.instance().backend()
        strength = backend.password_strength(self.method, *self.parameters)
        # We use Diceware only for locking our vaults. Because we know we
        # do proper salting and key stretching, we add 20 extra bits.
        strength += 20
        if strength < 70:
            strength = StrengthIndicator.Poor
        elif strength < 94:
            strength = StrengthIndicator.Good
        else:
            strength = StrengthIndicator.Excellent
        self.strength.setStrength(strength)


class RandomPasswordConfiguration(PasswordConfiguration):
    """Configuration for random password generation."""

    stylesheet = """
        PasswordConfiguration { border: 1px solid grey; }
    """

    def __init__(self, parent=None):
        super(RandomPasswordConfiguration, self).__init__('random', parent)
        self.parameters = [12, '[a-z][A-Z][0-9]']
        self.addWidgets()
        self.setFixedSize(self.sizeHint())
        self.setStyleSheet(self.stylesheet)

    def addWidgets(self):
        grid = QGridLayout()
        self.setLayout(grid)
        grid.setColumnMinimumWidth(1, 10)
        label = QLabel('Length', self)
        grid.addWidget(label, 0, 0)
        spinbox = NoSelectSpinbox(self)
        spinbox.setSuffix(' characters')
        spinbox.setMinimum(6)
        spinbox.setMaximum(20)
        grid.addWidget(spinbox, 0, 2, 1, 2)
        label = QLabel('Characters')
        grid.addWidget(label, 1, 0)
        def updateInclude(s):
            def stateChanged(state):
                self.updateInclude(state, s)
            return stateChanged
        lower = QCheckBox('Lower')
        grid.addWidget(lower, 1, 2)
        lower.stateChanged.connect(updateInclude('[a-z]'))
        upper = QCheckBox('Upper')
        grid.addWidget(upper, 1, 3)
        upper.stateChanged.connect(updateInclude('[A-Z]'))
        digits = QCheckBox('Digits')
        grid.addWidget(digits, 2, 2)
        digits.stateChanged.connect(updateInclude('[0-9]'))
        special = QCheckBox('Special')
        grid.addWidget(special, 2, 3)
        special.stateChanged.connect(updateInclude('[!-/]'))
        label = QLabel('Security', self)
        grid.addWidget(label, 3, 0)
        strength = StrengthIndicator(self)
        grid.addWidget(strength, 3, 2)
        self.strength = strength
        spinbox.valueChanged.connect(self.setLength)
        spinbox.setValue(self.parameters[0])
        lower.setChecked('[a-z]' in self.parameters[1])
        upper.setChecked('[A-Z]' in self.parameters[1])
        digits.setChecked('[0-9]' in self.parameters[1])
        special.setChecked('[!-/]' in self.parameters[1])

    @Slot(int)
    def setLength(self, length):
        self.parameters[0] = length
        self.parametersChanged.emit(self.method, self.parameters)
        self.updateStrength()

    @Slot()
    def updateInclude(self, enable, s):
        if enable and s not in self.parameters[1]:
            self.parameters[1] += s
        elif not enable:
            self.parameters[1] = self.parameters[1].replace(s, '')
        self.parametersChanged.emit(self.method, self.parameters)
        self.updateStrength()

    @Slot()
    def updateStrength(self):
        backend = QApplication.instance().backend()
        strength = backend.password_strength(self.method, *self.parameters)
        # We do not know if the remote site does key stretching or salting.
        # So we only give a Good rating if the entropy takes the password
        # out of reach of the largest Rainbow tables.
        if strength < 60:
            strength = StrengthIndicator.Poor
        elif strength < 84:
            strength = StrengthIndicator.Good
        else:
            strength = StrengthIndicator.Excellent
        self.strength.setStrength(strength)


class PopupButton(QPushButton):
    """A button with a popup.

    The popup will be displayed just below the button after the user
    keeps the button pressed for 500 msecs.
    """

    def __init__(self, text, parent=None):
        super(PopupButton, self).__init__(text, parent)
        timer = QTimer()
        timer.setSingleShot(True)
        timer.setInterval(500)
        timer.timeout.connect(self.showPopup)
        self.timer = timer
        self.popup = None

    # I would have preferred to implement the menu indicator by overriding
    # initStyleOption(), and nothing else, but it doesn't work. The C++
    # ::paintEvent() and ::sizeHint() are not able to call into it. So we need
    # to provide our own paintEvent() and sizeHint() too.

    def initStyleOption(self, option):
        super(PopupButton, self).initStyleOption(option)
        option.features |= option.HasMenu

    def paintEvent(self, event):
        p = QStylePainter(self)
        opts = QStyleOptionButton()
        self.initStyleOption(opts)
        p.drawControl(QStyle.CE_PushButton, opts)

    def sizeHint(self):
        size = super(PopupButton, self).sizeHint()
        fm = QFontMetrics(QApplication.instance().font())
        width = fm.width(self.text())
        opts = QStyleOptionButton()
        self.initStyleOption(opts)
        style = self.style()
        dw = style.pixelMetric(QStyle.PM_MenuButtonIndicator, opts, self)
        size.setWidth(width + dw + 10)
        return size

    def mousePressEvent(self, event):
        self.timer.start()
        super(PopupButton, self).mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self.timer.stop()
        super(PopupButton, self).mouseReleaseEvent(event)

    def setPopup(self, popup):
        popup.setParent(None)
        popup.setWindowFlags(Qt.Popup)
        popup.hide()
        # Install a closeEvent() on the popup that raises the button.
        def closeEvent(*args):
            self.setDown(False)
        popup.closeEvent = closeEvent
        self.popup = popup

    @Slot()
    def showPopup(self):
        if not self.popup:
            return
        pos = QPoint(self.width(), self.height())
        pos = self.mapToGlobal(pos)
        size = self.popup.size()
        self.popup.move(pos.x() - size.width(), pos.y())
        self.popup.show()


class GeneratePasswordButton(PopupButton):
    """A password generation button.

    A password is generated each time the user clicks the button.
    """

    def __init__(self, text, popup, parent=None):
        super(GeneratePasswordButton, self).__init__(text, parent)
        self.method = popup.method
        self.parameters = popup.parameters
        self.setPopup(popup)
        popup.parametersChanged.connect(self.parametersChanged)
        self.clicked.connect(self.generate)

    @Slot(str, list)
    def parametersChanged(self, method, parameters):
        self.method = method
        self.parameters = parameters
        self.generate()

    @Slot()
    def generate(self):
        backend = QApplication.instance().backend()
        password = backend.generate_password(self.method, *self.parameters)
        self.passwordGenerated.emit(password)

    passwordGenerated = Signal(str)
