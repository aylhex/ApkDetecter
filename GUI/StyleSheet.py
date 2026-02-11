
# Modern Dark Theme for ApkDetecter
import platform

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
    QSS = QSS_COMMON + QSS_WIN_OVERRIDES
else:
    # Default to Mac/Linux style
    QSS = QSS_COMMON + QSS_MAC_OVERRIDES
