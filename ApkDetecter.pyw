#-*-encoding:utf-8-*-
__author__ = 'Andy'
import os
import time
import tempfile
import io
import sys
import hashlib
import thread
import shutil
from PyQt4 import QtCore, QtGui
from AnalysisXML.AXML import AXML
from DexInfo import DexInfoForm
from ApkInfo import MyApkInfoForm
from AnalysisDEX.InitDEX import InitDEX
from CheckProtect import CheckProtect
from AnalysisCSN.CSN import CSN
from GUI.apkdetecter_ui import Ui_APKDetecter




class ApkDetecterForm(QtGui.QMainWindow):
    def __init__(self, parent = None):
        QtGui.QWidget.__init__(self, parent)
        #super(ApkDetecterForm, self).__init__(parent)
        self._want_to_close = True
        self.dexheader = {}
        self.loadfile_path = ""
        #self.unpackDir = tempfile.mktemp()
        self.unpackDir = ur"c:\APK"
        isExists = os.path.exists(self.unpackDir)
        if not isExists:
            os.makedirs(ur"c:\APK")

        self.ui = Ui_APKDetecter()
        self.ui.setupUi(self)

        QtCore.QObject.connect(self.ui.file_open, QtCore.SIGNAL("clicked()"), self.file_dialog)
        self.ui.apk_info.clicked.connect(self.apkinfo_dialog)
        self.ui.extend_info.clicked.connect(self.extendinfo_dialog)

    def closeEvent(self, evnt):
        if self._want_to_close:
            super(ApkDetecterForm, self).closeEvent(evnt)
            self.clearfiles(self.unpackDir)
            print "Andy"


    def probar_thread(self, no, interval):

        for a in range(no, interval):
            time.sleep(0.1)
            self.ui.progressBar.setValue(a)
        thread.exit_thread()

    def unzip(self, apkpath):
        apkpath = unicode(apkpath, "utf8")
        cmd = "tool\\7z.exe x %s -y -o%s *.dex AndroidManifest.xml lib META-INF assets"
        print cmd % (apkpath, self.unpackDir)
        self.ui.progressBar.setMaximum(29)
        thread.start_new_thread(self.probar_thread, (3, 30))
        os.system(cmd % (apkpath, self.unpackDir))


    def Init_Main_text(self):
        self.ui.te_dex_flag.clear()
        self.ui.te_dexheader_size.clear()
        self.ui.te_endiantag.clear()
        self.ui.te_file_size.clear()
        self.ui.te_linkoff.clear()
        self.ui.te_linksize.clear()
        self.ui.te_protect.clear()

    def Init_Apkinfo_text(self):
        self.apkinfo.ui.edt_file.setText("")
        self.apkinfo.ui.edt_serial_num.setText("")
        self.apkinfo.ui.edt_publisher.setText("")
        self.apkinfo.ui.edt_issuer.setText("")
        self.apkinfo.ui.edt_dexmd5.setText("")
        self.apkinfo.ui.edt_apkmd5.setText("")
        self.apkinfo.ui.edt_package.setText("")
        self.apkinfo.ui.edt_version.setText("")
        self.apkinfo.ui.edt_version_num.setText("")
        self.apkinfo.ui.edt_version_need.setText("")

    def Init_DexInfo_text(self):
        self.dexinfo.ui.text_magic.setText("")
        self.dexinfo.ui.text_checksum.setText("")
        self.dexinfo.ui.text_file_size.setText("")
        self.dexinfo.ui.text_header_size.setText("")
        self.dexinfo.ui.text_endian_tag.setText("")
        self.dexinfo.ui.text_link_size.setText("")
        self.dexinfo.ui.text_link_off.setText("")
        self.dexinfo.ui.text_map_off.setText("")
        self.dexinfo.ui.text_string_ids_size.setText("")
        self.dexinfo.ui.text_string_ids_off.setText("")
        self.dexinfo.ui.text_type_ids_size.setText("")
        self.dexinfo.ui.text_type_ids_off.setText("")
        self.dexinfo.ui.text_proto_ids_size.setText("")
        self.dexinfo.ui.text_proto_ids_off.setText("")
        self.dexinfo.ui.text_field_ids_size.setText("")
        self.dexinfo.ui.text_field_ids_off.setText("")
        self.dexinfo.ui.text_method_ids_size.setText("")
        self.dexinfo.ui.text_method_ids_off.setText("")
        self.dexinfo.ui.text_class_defs_size.setText("")
        self.dexinfo.ui.text_class_defs_off.setText("")
        self.dexinfo.ui.text_data_size.setText("")
        self.dexinfo.ui.text_data_off.setText("")
        self.dexinfo.ui.text_sha.setText("")

    def clearfiles(self, delDir):
        delList = []
        delList = os.listdir(delDir)

        for f in delList:
            filePath = os.path.join(delDir, f)
            if os.path.isfile(filePath):
                os.remove(filePath)
            elif os.path.isdir(filePath):
                shutil.rmtree(filePath, True)
        shutil.rmtree(delDir)



    def file_dialog(self):
        fd = QtGui.QFileDialog(self)

        self.Init_Main_text()
        self.loadfile_path = u""
        self.loadfile_path = fd.getOpenFileName()
        #self.loadfile_path = unicode(self.loadfile_path, "utf8")
        self.loadfile_path = self.loadfile_path.replace("/", os.path.sep)

        if self.loadfile_path != u"":
            self.clearfiles(self.unpackDir)
            self.ui.te_path.setText(self.loadfile_path)
            self.unzip(self.loadfile_path)
            obj = CheckProtect(self.unpackDir)

            protect_flag = obj.check_protectflag()

            dexobj = InitDEX()
            self.dexheader ={}
            self.dexheader = dexobj.getDexInfo(self.unpackDir + os.path.sep + "classes.dex")

            self.ui.te_dex_flag.setText(self.dexheader["header_magic"])
            self.ui.te_dexheader_size.setText(self.dexheader["header_headerSize"])
            self.ui.te_endiantag.setText(self.dexheader["header_endianTag"])
            self.ui.te_file_size.setText(self.dexheader["header_fileSize"])
            self.ui.te_linkoff.setText(self.dexheader["header_linkOff"])
            self.ui.te_linksize.setText(self.dexheader["header_linkSize"])
            self.ui.te_protect.setText(protect_flag)

        else:
            return

    def GetFileMd5(self, path):
        try:
            file = open(path, 'rb')
            md5 = hashlib.md5()
            strRead = ""
            while True:
                strRead = file.read(8096)
                if not strRead:
                    break
                md5.update(strRead)
            #read file finish
            strMd5 = md5.hexdigest()
            file.close()
            return strMd5
        except:
            return u"Sorry,计算出错!"





    def apkinfo_dialog(self):
        self.apkinfo = MyApkInfoForm()
        self.Init_Apkinfo_text()
        csn_path = self.unpackDir + os.path.sep + "META-INF"
        if os.path.isdir(csn_path):
            f_list = os.listdir(csn_path)

            for file_name in f_list:
                if os.path.splitext(file_name)[1] == '.RSA' or os.path.splitext(file_name)[1] == '.DSA':
                    csn_path = csn_path + os.path.sep + file_name
                    csn = CSN(csn_path)
                    self.apkinfo.ui.edt_file.setText(str(csn.get_size()))
                    self.apkinfo.ui.edt_serial_num.setText(str(csn.getCertificateSN()).upper())
                    self.apkinfo.ui.edt_publisher.setText(str(csn.getCertificateIDN()))
                    self.apkinfo.ui.edt_issuer.setText(str(csn.getCertificateSDN()))
                    break


        dex_path = self.unpackDir + os.path.sep + "classes.dex"
        if os.path.exists(dex_path):
            m = hashlib.md5()
            file = io.FileIO(dex_path, 'r')
            bytes = file.read(1024)
            while(bytes != b''):
                m.update(bytes)
                bytes = file.read(1024)
            file.close()
            dexmd5value = m.hexdigest()
            #print str(dexmd5value).upper()
            self.apkinfo.ui.edt_dexmd5.setText(str(dexmd5value).upper())

        apkpath = unicode(self.loadfile_path, "utf8")
        if os.path.isfile(apkpath) and self.loadfile_path != "":
            pass
        if self.loadfile_path != "":
            #apkpath = unicode(self.loadfile_path, "utf8")

            apkmd5value = self.GetFileMd5(self.loadfile_path)

            # m = hashlib.md5()
            # file = io.FileIO(self.loadfile_path, 'r')
            # bytes = file.read(1024)
            # while(bytes != b''):
            #     m.update(bytes)
            #     bytes = file.read(1024)
            # file.close()
            # apkmd5value = m.hexdigest()
            self.apkinfo.ui.edt_apkmd5.setText(apkmd5value.upper())


        path = self.unpackDir + os.path.sep +"AndroidManifest.xml"

        if os.path.exists(path):
            axml_analysis = AXML(self.unpackDir + os.path.sep +"AndroidManifest.xml")
            if axml_analysis.get_filename_abs() == 'AndroidManifest':
                self.apkinfo.ui.edt_package.setText(axml_analysis.get_package())
                self.apkinfo.ui.edt_version.setText(axml_analysis.get_androidversion_name())
                self.apkinfo.ui.edt_version_num.setText(axml_analysis.get_androidversion_code())
                self.apkinfo.ui.edt_version_need.setText(axml_analysis.getMinSdkVersion())



        self.apkinfo.show()

    def extendinfo_dialog(self):
        self.dexinfo = DexInfoForm()
        self.Init_DexInfo_text()
        if self.dexheader.has_key("header_magic"):
            self.dexinfo.ui.text_magic.setText(self.dexheader["header_magic"])
            self.dexinfo.ui.text_checksum.setText(self.dexheader["header_checksum"])
            self.dexinfo.ui.text_file_size.setText(self.dexheader["header_fileSize"])
            self.dexinfo.ui.text_header_size.setText(self.dexheader["header_headerSize"])
            self.dexinfo.ui.text_endian_tag.setText(self.dexheader["header_endianTag"])
            self.dexinfo.ui.text_link_size.setText(self.dexheader["header_linkSize"])
            self.dexinfo.ui.text_link_off.setText(self.dexheader["header_linkOff"])
            self.dexinfo.ui.text_map_off.setText(self.dexheader["header_mapOff"])
            self.dexinfo.ui.text_string_ids_size.setText(self.dexheader["header_stringIdsSize"])
            self.dexinfo.ui.text_string_ids_off.setText(self.dexheader["header_stringIdsOff"])
            self.dexinfo.ui.text_type_ids_size.setText(self.dexheader["header_typeIdsSize"])
            self.dexinfo.ui.text_type_ids_off.setText(self.dexheader["header_typeIdsOff"])
            self.dexinfo.ui.text_proto_ids_size.setText(self.dexheader["header_protoIdsSize"])
            self.dexinfo.ui.text_proto_ids_off.setText(self.dexheader["header_protoIdsOff"])
            self.dexinfo.ui.text_field_ids_size.setText(self.dexheader["header_fieldIdsSize"])
            self.dexinfo.ui.text_field_ids_off.setText(self.dexheader["header_fieldIdsOff"])
            self.dexinfo.ui.text_method_ids_size.setText(self.dexheader["header_methodIdsSize"])
            self.dexinfo.ui.text_method_ids_off.setText(self.dexheader["header_methodIdsOff"])
            self.dexinfo.ui.text_class_defs_size.setText(self.dexheader["header_classDefsSize"])
            self.dexinfo.ui.text_class_defs_off.setText(self.dexheader["header_classDefsOff"])
            self.dexinfo.ui.text_data_size.setText(self.dexheader["header_dataSize"])
            self.dexinfo.ui.text_data_off.setText(self.dexheader["header_dataOff"])
            self.dexinfo.ui.text_sha.setText(self.dexheader["header_signature"])
        self.dexinfo.show()



if __name__ == "__main__":

    app = QtGui.QApplication(sys.argv)
    myapp = ApkDetecterForm()
    myapp.show()
    sys.exit(app.exec_())