#-*- coding:utf-8-*-
__author__ = 'Andy'
import sys

from PyQt4 import QtGui

from GUI.apkinfo_ui import Ui_ApkInfo

class MyApkInfoForm(QtGui.QMainWindow):
    def __init__(self, parent = None):
        QtGui.QWidget.__init__(self, parent)
        self.ui = Ui_ApkInfo()
        self.ui.setupUi(self)




if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    myapp = MyApkInfoForm()
    myapp.show()
    sys.exit(app.exec_())