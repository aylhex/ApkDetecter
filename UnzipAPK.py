#-*- coding:utf-8-*-
__author__ = 'Andy'
import os
import struct
import tempfile
import subprocess
from platform import system

class UnzipAPK():

    def __init__(self, apkPath):
        self.unpackDir = apkPath
        self.getdexcontent()
        #self.Init_dexHeader()
        #self.unpackxml()
        self.dexdump()


    def getclassname(self):
        import codecs
        #dexdump_str = codecs.open(self.unpackDir + os.path.sep +'classes.txt', 'r', 'utf8').read()
        dexdump_str = codecs.open(self.unpackDir + os.path.sep +'classes.txt', 'rb').read()
        class_name_dict = {}
        buf_result = dexdump_str.split("Class #")
        for class_file in buf_result:
            try:
                class_code = class_file.split("\n")
                for smali in class_code:
                    if "  Class descriptor  :" in smali:
                          class_name = smali.split("'")[1][1:-1].replace("/", ".")
                          class_name_dict[class_name] = ""
                          break
            except:
                pass

        return class_name_dict

    def unpackxml(self):
        cmd = "java -jar tool\\AXMLPrinter2.jar %s > %s"
        xmlpath = os.path.join(self.unpackDir, "AndroidManifest.xml")
        if os.path.exists(xmlpath):
            try:
                os.system(cmd % (xmlpath, self.unpackDir + os.path.sep + "AndroidManifest_unpack.xml"))
                os.remove(xmlpath)
                self.xmlPath = self.unpackDir + os.path.sep + "AndroidManifest_unpack.xml"
                xmlfile_object = open(self.xmlPath)
                self.xml_content = xmlfile_object.read()
            except:
                pass


    def getdexcontent(self):

        self.dexcontent = open(self.unpackDir + os.path.sep +"classes.dex", 'rb').read()

    def getpackagename(self):
        fr = open(self.xmlPath, 'r')
        packagename = ""
        for line in fr:
            pos = line.find('package="')
            if pos > 0:
                packagename = line[pos+9:-1].strip('"')
        return packagename


    # def unzip(self):
    #     cmd = "tool\\7z.exe x %s -y -o%s *.dex AndroidManifest.xml lib META-INF assets"
    #     print cmd % (self.apkPath, self.unpackDir)
    #     os.system(cmd % (self.apkPath, self.unpackDir))

    def unpackxml(self):
        cmd = "java -jar tool\\AXMLPrinter2.jar %s > %s"
        xmlpath = os.path.join(self.unpackDir, "AndroidManifest.xml")
        if os.path.exists(xmlpath):
            try:
                os.system(cmd % (xmlpath, self.unpackDir + os.path.sep +"AndroidManifest_unpack.xml"))
                os.remove(xmlpath)
                self.xmlPath = self.unpackDir + os.path.sep +"AndroidManifest_unpack.xml"
                xmlfile_object = open(self.xmlPath)
                self.xml_content = xmlfile_object.read()
                #self.xml_content = self.xml_content.split('<')
            except:
                pass



    def dexdump(self):
        pathdexdump = ""
        if system() == "Windows":
            pathdexdump = "tool\\dexdump.exe"
        else:
            pathdexdump = subprocess.check_output(["which","dexdump"]).rstrip()

        cmd = '%s -d %s > %s'
        dexpath = os.path.join(self.unpackDir, "classes.dex")
        if os.path.exists(dexpath):
            os.system(cmd % (pathdexdump, dexpath, self.unpackDir + os.path.sep +"classes.txt"))

    def getallname(self):

        all_file_name = {}
        all_dir_name = {}
        for dirpath, dirnames, filenames in os.walk(self.unpackDir):
            for file in filenames:
                all_file_name[file] = ""

            for dir in dirnames:
                all_dir_name[dir] = ""

        return all_file_name, all_dir_name


# if __name__ == "__main__":
#     apkPath = r"D:\original.apk"
#     obj = UnzipAPK(apkPath)
