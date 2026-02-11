# -*- coding: utf-8 -*-
__author__ = 'Andy'

import sys
import os

# Add libs to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libs'))

from PyQt5 import QtWidgets
import StyleSheet
from GUI.MainForm import MainForm

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    
    # Set Style
    app.setStyle("Fusion")
    app.setStyleSheet(StyleSheet.QSS)
    
    # Main Window
    myapp = MainForm()
    myapp.show()
    
    sys.exit(app.exec_())
