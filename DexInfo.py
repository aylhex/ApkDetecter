#-*- coding:utf-8-*-
__author__ = 'Andy'
import sys

from PyQt4 import QtGui

from GUI.dexinfor_ui import Ui_DexInfo


class DexInfoForm(QtGui.QMainWindow):
    def __init__(self, parent = None):
        QtGui.QWidget.__init__(self, parent)
        self.ui = Ui_DexInfo()
        self.ui.setupUi(self)



if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    myapp = DexInfoForm()
    myapp.show()
    sys.exit(app.exec_())