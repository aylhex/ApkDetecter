#-*- coding:utf-8-*-
__author__ = 'Andy'

import os
from UnzipAPK import UnzipAPK
from AnalysisXML.AXML import AXML
class CheckProtect():

    def __init__(self, apkPath):
        #self.apkPath = r"D:\original.apk"
        self.apkPath = apkPath
        self.protectflag = ""
        self.protectflag_dict = {"libsecexe.so": u"该APK已加固=>梆梆加固", "libAPKProtect.so": u"该APK已加固=>APKProtect加固",
                           "libprotectClass.so": u"该APK已加固=>360加固", "libNSaferOnly.so": u"该APK已加固=>通付盾加固",
                           "libnqshield.so": u"该APK已加固=>网秦加固", "libshell.so": u"该APK已加固=>腾讯加固",
                           "ijiami.dat": u"该APK已加固=>爱加密加固", "libddog.so": u"该APK已加固=>娜迦加固",
                           "libmobisec.so": u"该APK已加固=>阿里加固", "libbaiduprotect.so": u"该APK已加固=>百度加固"}

    def getactivity(self, path):
        axml_analysis = AXML(path + os.path.sep +"AndroidManifest.xml")
        mainfast = axml_analysis.get_xml()
        packagename = axml_analysis.get_package()
        xml_content = mainfast.split("<application")[1:]
        info_list = xml_content[0].split("<activity")[1:]
        activity = {}
        for tmp in info_list:
            tmp = tmp.split('android:name=')[1]
            tmp = tmp.split('" ')[0].replace('"', "")
            if ">" in tmp:
                tmp = tmp.split('>')[0]
            if tmp.startswith("."):
                activity[packagename + tmp] = ""
            elif tmp.startswith(packagename):
                activity[tmp] = ""
            else:
                activity[packagename + '.' + tmp] = ""
        return activity

    def check_protectflag(self):

        self.protectflag = ""

        obj = UnzipAPK(self.apkPath)
        dir_name = {}
        file_name = {}

        activites = self.getactivity(self.apkPath)
        class_names = obj.getclassname()

        all_file_name, all_dir_name = obj.getallname()

        for file in all_file_name:
            file_name[file] = ""

        for dir in all_dir_name:
            dir_name[dir] = ""


        for key in self.protectflag_dict.keys():
            if file_name.has_key(key):
                self.protectflag = self.protectflag + self.protectflag_dict[key]

        if file_name.has_key("key.dat") and all_dir_name.has_key("apkprotect.com"):
            if self.protectflag == "" or (u"APKProtect加固" not in self.protectflag):
                self.protectflag = self.protectflag + u"APKProtect加固"

        if self.protectflag != "":
            return self.protectflag
        else:
            self.flag = 0
            for activity in activites.keys():
                # self.flag = 0
                if class_names.has_key(activity):
                    pass
                else:
                    self.flag  = 1

            if self.protectflag == "" and self.flag == 1:
                self.protectflag = u"疑似未知加密"

            if self.protectflag == "":
                self.protectflag = u"该APK未加密"

            return self.protectflag



if __name__ == "__main__":
    obj = CheckProtect()
    obj.check_protectflag()