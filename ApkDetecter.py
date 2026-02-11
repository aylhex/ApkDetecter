# -*- coding: utf-8 -*-
__author__ = 'Andy'

import sys
import os
import platform
import ctypes

# === FIX FOR PYINSTALLER NOCONSOLE ===
# Some libraries (like androguard) try to write to stdout/stderr even if it's None.
# We redirect them to a dummy writer if they are None.
class NullWriter:
    def write(self, text):
        pass
    def flush(self):
        pass
    def isatty(self):
        return False

if sys.stdout is None:
    sys.stdout = NullWriter()
if sys.stderr is None:
    sys.stderr = NullWriter()
# =====================================

# Add libs to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libs'))

from PyQt5 import QtWidgets, QtGui, QtCore
# from GUI import StyleSheet  <-- REMOVED
from GUI.MainForm import MainForm

# === INLINED STYLESHEET TO AVOID IMPORT ERRORS ===
QSS_COMMON = """
/* General Window */
QMainWindow, QDialog, QWidget {
    background-color: #2b2b2b;
    color: #e0e0e0;
    font-family: "Segoe UI", "Arial", sans-serif;
}

/* GroupBox */
QGroupBox {
    border: 1px solid #3d3d3d;
    border-radius: 6px;
    margin-top: 24px;
    font-weight: bold;
    color: #e0e0e0;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 5px;
    color: #4da6ff; /* Blue accent */
}

/* Labels */
QLabel {
    color: #cccccc;
}

/* TextBrowser / TextEdit / LineEdit */
QTextBrowser, QTextEdit, QLineEdit {
    background-color: #363636;
    border: 1px solid #3d3d3d;
    border-radius: 4px;
    color: #ffffff;
    selection-background-color: #4da6ff;
}

QTextBrowser:disabled, QTextEdit:disabled {
    background-color: #2f2f2f;
    color: #909090;
    border: 1px solid #333333;
}

/* Push Buttons */
QPushButton {
    background-color: #3a3a3a;
    border: 1px solid #4a4a4a;
    border-radius: 4px;
    color: #e0e0e0;
    padding: 4px 12px;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #4a4a4a;
    border: 1px solid #5a5a5a;
}

QPushButton:pressed {
    background-color: #2a2a2a;
}

QPushButton#file_open {
    background-color: #007acc;
    color: white;
    border: 1px solid #005c99;
}

QPushButton#file_open:hover {
    background-color: #008ae6;
}

QPushButton#file_open:pressed {
    background-color: #005c99;
}

/* Progress Bar */
QProgressBar {
    border: 1px solid #3d3d3d;
    border-radius: 4px;
    background-color: #363636;
    text-align: center;
    color: #e0e0e0;
}

QProgressBar::chunk {
    background-color: #007acc;
    border-radius: 3px;
}

/* ScrollBars */
QScrollBar:vertical {
    border: none;
    background: #2b2b2b;
    width: 10px;
    margin: 0px 0px 0px 0px;
}

QScrollBar::handle:vertical {
    background: #505050;
    min-height: 20px;
    border-radius: 5px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    border: none;
    background: #2b2b2b;
    height: 10px;
    margin: 0px 0px 0px 0px;
}

QScrollBar::handle:horizontal {
    background: #505050;
    min-width: 20px;
    border-radius: 5px;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
"""

QSS_WIN_OVERRIDES = """
/* Windows Specific Overrides for High DPI / Readability */
QMainWindow, QDialog, QWidget {
    font-size: 24px;
}

QGroupBox {
    font-size: 26px;
    margin-top: 36px;
}

QGroupBox::title {
    top: -24px;
    left: 10px;
}

QLabel {
    font-size: 24px;
}

QTextBrowser, QTextEdit, QLineEdit {
    font-size: 24px;
    padding: 10px;
}

QPushButton {
    padding: 8px 20px;
    min-height: 32px;
}

QScrollBar:vertical {
    width: 20px;
}

QScrollBar:horizontal {
    height: 20px;
}
"""

QSS_MAC_OVERRIDES = """
/* macOS Specific Overrides */
QLabel {
    font-size: 12px;
}
/* Other defaults are usually fine on Mac */
"""

if platform.system() == "Windows":
    GLOBAL_QSS = QSS_COMMON + QSS_WIN_OVERRIDES
else:
    # Default to Mac/Linux style
    GLOBAL_QSS = QSS_COMMON + QSS_MAC_OVERRIDES
# ===============================================

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

if __name__ == "__main__":
    # Fix for Windows Taskbar Icon
    if platform.system() == 'Windows':
        try:
            # Set AppUserModelID to ensure the taskbar icon is displayed correctly
            myappid = 'mycompany.myproduct.subproduct.version' # Arbitrary string
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception as e:
            pass

    app = QtWidgets.QApplication(sys.argv)
    
    # Set Style
    app.setStyle("Fusion")
    app.setStyleSheet(GLOBAL_QSS)

    # Set Application Icon (Global)
    logo_path = resource_path(os.path.join('Resources', 'logo.png'))
    if os.path.exists(logo_path):
        # Windows: Load icon directly (Best for Taskbar/Titlebar)
        if platform.system() == 'Windows':
            # Windows: Load the large icon directly. 
            # We avoid adding small sizes manually to prevent Windows from picking a low-res version.
            app.setWindowIcon(QtGui.QIcon(logo_path))
        else:
            # macOS/Linux: Use padding/scaling logic (Original logic)
            original_pixmap = QtGui.QPixmap(logo_path)
            
            if not original_pixmap.isNull():
                # Create a square canvas (transparent)
                size = 1024
                padded_pixmap = QtGui.QPixmap(size, size)
                padded_pixmap.fill(QtCore.Qt.transparent)
                
                # Calculate padding (scale to 80% of the canvas)
                scale_factor = 0.8
                new_w = int(size * scale_factor)
                new_h = int(size * scale_factor)
                x = (size - new_w) // 2
                y = (size - new_h) // 2
                
                painter = QtGui.QPainter(padded_pixmap)
                painter.setRenderHint(QtGui.QPainter.SmoothPixmapTransform)
                painter.setRenderHint(QtGui.QPainter.Antialiasing)
                
                painter.drawPixmap(x, y, new_w, new_h, original_pixmap)
                painter.end()
                
                app.setWindowIcon(QtGui.QIcon(padded_pixmap))
        
        # For macOS Dock icon (sometimes requires this specific call or packaging)
        try:
            # This is a workaround for Python not being a bundled app on macOS
            pass 
        except:
            pass
    
    # Main Window
    myapp = MainForm()
    myapp.show()
    
    sys.exit(app.exec_())
