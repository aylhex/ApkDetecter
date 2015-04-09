# -*- coding:utf-8 -*-
import os
import zipfile
from hashlib import md5, sha1, sha256
from base64 import b64encode
from platform import system, architecture
from xml.dom import minidom

from core import extraTools
from androguard.core.bytecodes import apk
from CheckProtect.androguard.core.bytecodes.dvm import *
from androguard.core.analysis.analysis import *
from configure import *


TOOLS = extraTools.myTools()
SYS = system()

if SYS == "Darwin":
    from CheckProtect.core.chilkatCert.mac import chilkat
if SYS == "Windows":
    if architecture()[0] == "32bit":
        from CheckProtect.core.chilkatCert.win32 import chilkat
    elif architecture()[0] == "64bit":
        from CheckProtect.core.chilkatCert.win64 import chilkat

CHILKATKEY = "ZIP87654321_135D44EDpH3I"


def GetZipFileChilkat(filename, OPT, savePath):
    zip = chilkat.CkZip()
    zip.UnlockComponent(CHILKATKEY)
    success = zip.OpenZip(filename)
    n = zip.get_NumEntries()

    for i in range(0, n):
        entry = zip.GetEntryByIndex(i)
        if re.compile(OPT).search(entry.fileName()):
            entry.ExtractInto(savePath)


def GetZipFile(filename, OPT, savePath):
    try:
        f = zipfile.ZipFile(filename, 'r')
        for i in f.namelist():
            if OPT in i:
                f.extract(i, savePath)
    except Exception, e:
        print e


MIN_SDK_VERSION = {
    "1": "Android 1.0",
    "2": "Android 1.1",
    "3": "Android 1.5",
    "4": "Android 1.6",
    "5": "Android 2.0",
    "6": "Android 2.0.1",
    "7": "Android 2.1-update1",
    "8": "Android 2.2",
    "9": "Android 2.3 - 2.3.2",
    "10": "Android 2.3.3 - 2.3.4",
    "11": "Android 3.0",
    "12": "Android 3.1",
    "13": "Android 3.2",
    "14": "Android 4.0.0 - 4.0.2",
    "15": "Android 4.0.3 - 4.0.4",
    "16": "Android 4.1 - 4.1.1",
    "17": "Android 4.2 - 4.2.2",
}

RISK_PERMISSION = {
    "android.permission.SEND_SMS": "可无提示直接发送短信",
    "android.permission.RECEIVE_SMS": "可监控短信接收",
    "android.permission.CALL_PRIVILEGED": "可无提示直接拨打电话",
    "android.permission.INTERNET": "具有完全的互联网访问权限",
    "android.permission.READ_CONTACTS": "可读取联系人信息",
    "android.permission.WRITE_CONTACTS": "可修改联系人信息",
    "android.permission.CHANGE_WIFI_STATE": "可修改手机当前WIFI设置",
    "android.permission.WRITE_EXTERNAL_STORAGE": "可对存储卡进行读写操作",
    "com.android.launcher.permission.INSTALL_SHORTCUT": "可创建程序快捷方式",
    "android.permission.READ_PHONE_STATE": "可读取手机状态和身份",
    "android.permission.INSTALL_PACKAGES": "可安装其它程序",
    "android.permission.READ_SMS": "读取短信或彩信",
    "android.permission.WRITE_SMS": "编辑短信或彩信",
    "android.permission.RESTART_PACKAGES": "重启应用程序",
    "android.permission.CALL_PHONE": "直接拨打电话",
    "android.permission.ACCESS_COARSE_LOCATION": "可获取当前粗略位置信息",
    "android.permission.ACCESS_FINE_LOCATION": "可获取当前精确位置信息",
}




class APK(apk.APK):
    # print a.get_android_manifest_axml().get_xml() #获取xml

    def getSize(self):
        return str(os.path.getsize(self.get_filename()))

    def getMd5(self, filename):
        return md5(open(filename, "rb").read()).hexdigest()

    def getSha1(self, filename):
        return sha1(open(filename, "rb").read()).hexdigest()

    def getSha256(self, filename):
        return sha256(open(filename, "rb").read()).hexdigest()

    def getDigest(self, filename):
        return b64encode(sha1(open(filename, "rb").read()).digest())

    def getListMd5(self, f, OPT):
        return md5(f.read(OPT, "rb")).hexdigest()

    def getListSha1(self, f, OPT):
        return sha1(f.read(OPT, "rb")).hexdigest()

    def getListSha256(self, f, OPT):
        return sha256(f.read(OPT, "rb")).hexdigest()

    def getListDigest(self, f, OPT):
        return b64encode(sha1(f.read(OPT, "rb")).digest())

    def getApkMd5(self):
        return self.getMd5(self.get_filename())

    def getApkSha1(self):
        return self.getSha1(self.get_filename())

    def getApkSha256(self):
        return self.getSha256(self.get_filename())

    def getDexMd5(self):
        OPT = "classes.dex"
        f = zipfile.ZipFile(self.get_filename(), 'r')
        return self.getListMd5(f, OPT)

    def getDexSha1(self):
        OPT = "classes.dex"
        f = zipfile.ZipFile(self.get_filename(), 'r')
        return self.getListSha1(f, OPT)

    def getDexSha256(self):
        OPT = "classes.dex"
        f = zipfile.ZipFile(self.get_filename(), 'r')
        return self.getListSha256(f, OPT)

    def getDexDigest(self):
        OPT = "classes.dex"
        f = zipfile.ZipFile(self.get_filename(), 'r')
        return self.getListDigest(f, OPT)

    def getManifestDigest(self):
        OPT = "META-INF/MANIFEST.MF"
        f = zipfile.ZipFile(self.get_filename(), 'r')
        return self.getListDigest(f, OPT)

    def getMinSdkVersion(self):
        minSdk = self.get_element("uses-sdk", "android:minSdkVersion")
        if minSdk:
            try:
                return MIN_SDK_VERSION[minSdk]
            except KeyError:
                return minSdk
        else:
            return "None"

    def getPermission(self):
        for i in self.xml:
            x = []
            if not self.xml[i].getElementsByTagName('uses-permission'):
                return []
            else:
                for item in self.xml[i].getElementsByTagName('uses-permission'):
                    x.append(item.getAttribute("android:name"))

            if len(x) > 0:
                return x

    def getRiskPermission(self):
        x = []
        permission = self.getPermission()

        if len(permission) == 0:
            return ["该程序未发现含有权限"]
        else:
            for i in permission:
                try:
                    if RISK_PERMISSION[i] not in x:
                        x.append(RISK_PERMISSION[i])
                except KeyError:
                    pass

        if len(x) > 0:
            return x
        else:
            return ["该程序未发现含有风险权限"]

    def getLogPath(self):
        savePath, fileType = os.path.splitext(self.get_filename())
        return savePath.strip(" ") + ".txt"

    def getSavePath(self):
        savePath, fileType = os.path.splitext(self.get_filename())
        return savePath.strip(" ")
        # return TOOLS.temp()

    def getFilename(self):
        filePath, filename = os.path.split(self.get_filename())
        return filename[:-4].strip(" ")

    def getMetaInf(self):
        OPT = "^(META-INF/)(.*)(\.RSA|\.DSA)$"
        GetZipFileChilkat(self.get_filename(), OPT, self.getSavePath())

    def getManifest(self):

        for parent, dirNames, fileNames in os.walk(self.getSavePath()):
            for fileName in fileNames:
                fileType = os.path.splitext(os.path.join(parent, fileName))[1]
                if fileType == "MANIFEST.MF":
                    return os.path.join(parent, fileName)

    def getSa(self):

        for parent, dirNames, fileNames in os.walk(self.getSavePath()):
            for fileName in fileNames:
                fileType = os.path.splitext(os.path.join(parent, fileName))[1]
                if fileType == ".RSA" or fileType == ".DSA":
                    return os.path.join(parent, fileName)

    def getCert(self):
        cmd = 'java -jar ' + '\"' + TOOLS.cert() + '\"' + ' \"' + self.getSa() + '\"'
        return os.popen(cmd).readlines()

    def getCertSN(self):
        cmd = 'java -jar ' + '\"' + TOOLS.certSN() + '\"' + ' \"' + self.getSa() + '\"'
        return os.popen(cmd).readlines()

    def getCertIDN(self):
        cmd = 'java -jar ' + '\"' + TOOLS.certIDN() + '\"' + ' \"' + self.getSa() + '\"'
        return os.popen(cmd).readlines()

    def getCertSDN(self):
        cmd = 'java -jar ' + '\"' + TOOLS.certSDN() + '\"' + ' \"' + self.getSa() + '\"'
        return os.popen(cmd).readlines()

    def getChilkatCertSN(self):
        self.getMetaInf()
        sa = self.getSa()

        cert = chilkat.CkCert()
        success = cert.LoadFromFile(sa)

        if success:
            return cert.serialNumber()
        else:
            return None

    def getChilkatCertIDN(self):
        sa = self.getSa()

        cert = chilkat.CkCert()
        success = cert.LoadFromFile(sa)

        if success:
            return 'C=' + cert.issuerC() + ',CN=' + cert.issuerCN() + ',DN=' + cert.issuerDN() + \
                   ',E=' + cert.issuerE() + ',L=' + cert.issuerL() + ',O=' + cert.issuerO() + \
                   ',OU=' + cert.issuerOU() + ',S=' + cert.issuerS()
        else:
            return None

    def getChilkatCertSDN(self):
        sa = self.getSa()

        cert = chilkat.CkCert()
        success = cert.LoadFromFile(sa)

        if success:
            return 'C=' + cert.subjectC() + ',CN=' + cert.subjectCN() + ',DN=' + cert.subjectDN() + \
                   ',E=' + cert.subjectE() + ',L=' + cert.subjectL() + ',O=' + cert.subjectO() + \
                   ',OU=' + cert.subjectOU() + ',S=' + cert.subjectS()
        else:
            return None

    def get_obj_certificate(self, filename):
        cert = chilkat.CkCert()
        f = self.get_file(filename)
        bytedata = chilkat.CkByteData()
        bytedata.append2(f, len(f))
        success = cert.LoadFromBinary(bytedata)
        return success, cert

    def get_certificate_loader(self):
        OPT = "^(META-INF/)(.*)(\.RSA|\.DSA)$"
        for i in self.zip.namelist():
            if re.compile(OPT).search(i):
                success, cert = self.get_obj_certificate(i)

        return success, cert

    def getCertificateSN(self):
        success, cert = self.get_certificate_loader()

        if success:
            x = []
            c = cert.serialNumber()
            for i in c:
                x.append(i)

            if x[0] == x[1] == '0':
                x = x[2:]
                return ''.join(x).lower()
            else:
                return ''.join(x).lower()

    def getCertificateIDN(self):
        success, cert = self.get_certificate_loader()
        if success:
            return 'C=' + cert.issuerC() + ', CN=' + cert.issuerCN() + ', DN=' + cert.issuerDN() + \
                   ', E=' + cert.issuerE() + ', L=' + cert.issuerL() + ', O=' + cert.issuerO() + \
                   ', OU=' + cert.issuerOU() + ', S=' + cert.issuerS()
        else:
            return None

    def getCertificateSDN(self):
        success, cert = self.get_certificate_loader()
        if success:
            return 'C=' + cert.subjectC() + ', CN=' + cert.subjectCN() + ', DN=' + cert.subjectDN() + \
                   ', E=' + cert.subjectE() + ', L=' + cert.subjectL() + ', O=' + cert.subjectO() + \
                   ', OU=' + cert.subjectOU() + ', S=' + cert.subjectS()
        else:
            return None

    def get_my_app_icon(self):
        """
            android:icon="@drawable/icon"
        """
        fp = os.path.join(self.getSavePath(), "AndroidManifest.xml")
        try:
            doc = minidom.parse(fp).documentElement
        except:
            return None

        for node in doc.childNodes:
            if node.nodeType == node.ELEMENT_NODE:
                if node.getAttribute("android:icon"):
                    label = node.getAttribute("android:icon")
                    if label[:10] != "@drawable/":
                        return None
                    else:
                        iconname = label[10:] + ".png"
                        flag = False

                        # if os.path.isdir(os.path.join(self.get_my_filepath(), "res\\drawable\\")):
                        #     icon = os.path.join(self.get_my_filepath(), "res\\drawable\\" + iconname)
                        #     shutil.copy(icon, self.get_my_filepath())
                        # elif os.path.isdir(os.path.join(self.get_my_filepath(), "res\\drawable-mdpi\\")):
                        #     icon = os.path.join(self.get_my_filepath(), "res\\drawable-mdpi\\" + iconname)
                        #     shutil.copy(icon, self.get_my_filepath())
                        # else: return 111111111111

    def getAppName(self):
        print self.get_android_resources()

    def get_my_node_date(self, fp, nodevalue):
        doc = minidom.parse(fp)
        for i in doc.getElementsByTagName("string"):
            if i.getAttribute("name") == nodevalue:
                return i.firstChild.toxml()

    def get_my_app_name_new(self):
        key = "title"
        a = self.get_android_resources()
        # print a.get_string(a.get_packages_names()[0], key)[1].decode().encode('utf8')
        print 1
        # print a.get_strings_resources()
        # print a.get_packages_names()
        s = a.get_string(a.get_packages_names()[0], key)
        print s
        # print chardet.detect(s)
        # print s.decode('ascii').encode('ascii'
        # print s.decode('ascii').encode('utf-8')
        print isinstance(s, unicode)
        print isinstance(key, unicode)
        print s
        detaillfile = open("C:\\Users\\iWork\\Desktop\\simpleApk\\detail.txt", "w")
        detaillfile.write(s)
        detaillfile.close()
        print 2
        # print sys.getdefaultencoding()
        for i in a.get_string(a.get_packages_names()[0], key):
            print len(i)
            print i
            # print  str(i).decode("utf-8")

    def get_my_app_name(self):
        #=======================================================================
        # key = "app_name"
        # a = self.get_android_resources()
        #  return a.get_string(a.get_packages_names()[0], key)[1]
        #=======================================================================
        """

        """
        fp = os.path.join(self.get_my_filepath(), "AndroidManifest.xml")
        valueszh = os.path.join(self.get_my_filepath(), "res\\values-zh\\strings.xml")
        values = os.path.join(self.get_my_filepath(), "res\\values\\strings.xml")
        try:
            doc = minidom.parse(fp).documentElement
        except:
            return None

        for node in doc.childNodes:
            if node.nodeType == node.ELEMENT_NODE:
                """
                if "@string/" not in node.getAttribute("android:label"):
                    return node.getAttribute("android:label")
                """
                if node.getAttribute("android:label"):
                    label = node.getAttribute("android:label")
                    if label[:8] != "@string/":
                        return label
                    else:
                    # if "@string/" in node.getAttribute("android:label"):
                    #     label = node.getAttribute("android:label")
                        try:
                            return self.get_my_node_date(values, label[8:])
                        except:
                            try:
                                return self.get_my_node_date(valueszh, label[8:])
                            except:
                                return None
class ANALYSIS(apk.APK):
    # def __init__(self):
    #     a, d, x = AnalyzeAPK(self.get_filename())
    #     self.a = a
    #     self.d = d
    #     self.x = x

    def get_name(self):
        return os.path.splitext(os.path.split(self.get_filename())[1])[0]

    def checkManifest(self):
        """
            1 有activity，但是程序没有入口
            2 有入口
            3 无图标
        """
        self.result = [self.get_name()]   # +
        self.result.append("1")
        # self.result = ["1"]

        for i in self.xml:
            if self.xml[i].getElementsByTagName("activity"):
                x = set()
                y = set()
                for item in self.xml[i].getElementsByTagName("activity"):
                    for sitem in item.getElementsByTagName("action"):
                        val = sitem.getAttribute("android:name")
                        if val == "android.intent.action.MAIN":
                            x.add(item.getAttribute("android:name"))

                    for sitem in item.getElementsByTagName("category"):
                        val = sitem.getAttribute("android:name")
                        if val == "android.intent.category.LAUNCHER":
                            y.add(item.getAttribute("android:name"))

                z = x.intersection(y)

                if len(z) > 0:
                    self.result[1] = "2"
                    # self.result[0] = "2"
                    self.result.append(self.format_value(z.pop()))
                    return self.result
                else:
                    self.result.append("0")
                    # self.result.append("0")
                    return self.result
            else:
                self.result[1] = "3"
                # self.result[0] = "3"
                self.result.append("0")
                return self.result

    def getDetailServices(self):
        """
            Return the detail of the services
            :rtype: dict
            {'name1': ['action1', 'action2', ...],
             'name2': ['action1', 'action2', ...], ...
            }
        """
        x = {}
        y = []

        for i in self.xml:
            for item in self.xml[i].getElementsByTagName("service"):
                val = self.format_value(item.getAttribute("android:name"))
                if not item.getElementsByTagName("action"):
                    y.append("None")
                    x[val] = y
                    y = []
                else:
                    for sitem in item.getElementsByTagName("action"):
                        a = sitem.getAttribute("android:name")
                        y.append(self.format_value(a))
                        x[val] = y
                    y = []

        if x:
            return x
        else:
            return "None"

    def getDetailReceivers(self):
        """
            Return the detail of the receivers
            :rtype: dict
            {'name1': ['action1,Priority1', 'action2,Priority2', ...],
             'name2': ['action1,Priority1', 'action2,Priority2', ...], ...
            }

        """
        x = {}
        y = []

        for i in self.xml:
            for item in self.xml[i].getElementsByTagName("receiver"):
                val = self.format_value(item.getAttribute("android:name"))
                if not item.getElementsByTagName("action"):
                    # y.append("None,None")
                    y.append(["None", "None"])
                    x[val] = y
                    y = []
                else:
                    for sitem in item.getElementsByTagName("action"):
                        a = sitem.getAttribute("android:name")
                        p = sitem.parentNode.getAttribute("android:priority")
                        if not p:
                            p = "None"
                            # y.append(self.format_value(a) + "," + p)
                        y.append([self.format_value(a), p])
                        x[val] = y
                    y = []

        if x:
            return x
        else:
            return "None"

    def checkAPI(self):
        cmd = "java -jar " + TOOLS.SSS() + " " + TOOLS.parser() + " " + "\"" + self.get_filename() + "\" "
        return os.popen(cmd).readlines()

    def getSavePath(self):
        savePath, fileType = os.path.splitext(self.get_filename())
        return savePath.strip(" ")

    def getShDex(self):
        self.getDex()
        if SYS == "Darwin":
            cmd = "sh " + "\"" + TOOLS.dex2jar() + "\"" + " " + "\"" + \
                  os.path.join(self.getSavePath(), "classes.dex") + "\""
        if SYS == "Windows":
            cmd = TOOLS.dex2jar() + " " + "\"" + os.path.join(self.getSavePath(), "classes.dex") + "\""
        os.system(cmd)
        copy_cmd = 'copy /Y "%s" "%s"' % (self.getSavePath() + '.apk', self.getSavePath())
        print os.popen(copy_cmd).read()
        del_cmd = 'del "%s" /Q' % self.getSavePath() + '.apk'
        print os.popen(del_cmd).read()
        # oCmd = TOOLS.jdGui() + " \"" + os.path.join(self.getSavePath(), "classes_dex2jar.jar") + "\""
        # os.system(oCmd)

    def getDex(self):
        OPT = "classes.dex"
        GetZipFileChilkat(self.get_filename(), OPT, self.getSavePath())

    def getSmali(self):
        cmd = "java -jar " + TOOLS.apkTool() + " d " + " -f " + "\"" + self.get_filename() + "\" " + "\"" + \
              os.path.join(self.getSavePath(), "Baksmali") + "\""
        os.system(cmd)

    def checkMasterKey(self):
        zip = chilkat.CkZip()
        zip.UnlockComponent("ZIP87654321_135D44EDpH3I")
        success = zip.OpenZip(self.get_filename())

        x = []
        d = []

        n = zip.get_NumEntries()

        for i in range(0, n):
            entry = zip.GetEntryByIndex(i)
            if re.compile("^(AndroidManifest\.xml)$").search(entry.fileName()):
                x.append(i)
            if re.compile("^(classes\.dex)$").search(entry.fileName()):
                d.append(i)

        if len(x) > 1 or len(d) > 1:
            return True
        else:
            return False

    def checkbangbang(self):
        zip = chilkat.CkZip()
        zip.UnlockComponent("ZIP87654321_135D44EDpH3I")
        success = zip.OpenZip(self.get_filename())

        n = zip.get_NumEntries()

        for i in range(0, n):
            entry = zip.GetEntryByIndex(i)
            if re.compile("libsecexe.so").search(entry.fileName()):
                return True
            else:
                pass

    def get_suspicious_file(self):
        result_dict = {}
        z = []
        d = []
        e = []

        f = zipfile.ZipFile(self.filename, 'r')

        for i in f.namelist():
            fd = f.read(i, 'r')
            f_bytes = fd[:7]
            magic = self.get_magic_raw(f_bytes)

            if magic == 'ZIP':
                z.append(i)
            if magic == 'DEX':
                d.append(i)
            if magic == 'ELF':
                e.append(i)

        result_dict['DEX'] = d
        result_dict['ZIP'] = z
        result_dict['ELF'] = e
        return result_dict

    def get_magic_raw(self, raw):
        val = None
        f_bytes = raw[:7]

        if f_bytes[0:2] == "PK":
            val = "ZIP"
        elif f_bytes[0:3] == "dex":
            val = "DEX"
        elif f_bytes[0:7] == "\x7fELF\x01\x01\x01":
            val = "ELF"
            #elif f_bytes[0:4] == "\x03\x00\x08\x00":
        #    val = "AXML"

        return val

    def check_black_csn(self, csn, black_list_csn=BLACK_LIST_CSN):
        for k, v in black_list_csn:
            if k == csn:
                return v

    def get_cm_method_format(self, get_cm_method):
        return get_cm_method[0] + '->' + get_cm_method[1] + get_cm_method[2][0] + get_cm_method[2][1]

    def formatString(self, method, className, descriptor):
        return method + '->' + className + descriptor

    def get_detail_api(self, result):
        return get_detail_result(result)

    def get_all_api(self):
        a, d, x = AnalyzeAPK(self.get_filename())

        api_string = self.get_api_string(d, x)
        api_string_string = self.get_api_string_string(d, x)

        api_method = self.get_api_method(x)
        api_method_string = self.get_api_method_string(d, x)
        api_method_field = self.get_api_method_field(d, x)

        return [api_string, api_string_string, api_method, api_method_string, api_method_field]

    def get_api_string(self, d, x, string_list=STRING_LIST):
        """
        Return Type
            {
                DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                ...
            }
        """
        result = {}
        length = len(string_list)

        i = 0
        while i < length:
            key, description = string_list[i]
            tem = {}

            for s, _ in x.tainted_variables.get_strings():
                l = []
                # if key in s.get_info():
                if re.compile(key).search(s.get_info()):
                    for path in s.get_paths():
                        access, idx = path[0]
                        m_idx = path[1]
                        methodName = self.get_cm_method_format(d.get_cm_method(m_idx))
                        l.append(methodName)
                        l = list(set(l))
                    tem[s.get_info()] = l
            i += 1

            if description in result:
                result[description] = dict(result[description], **tem)
            else:
                if tem:
                    result[description] = tem

        return result

    def get_api_method(self, x, method_dict=METHOD_DICT):
        """
        Return Type
            {
                DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                ...
            }
        """
        result = {}

        for class_name, method_names in method_dict.iteritems():
            for method_name, description in method_names:
                l = []
                tem = {}
                results = x.tainted_packages.search_methods(class_name, method_name, ".")
                for i in results:
                    className = self.formatString(i.get_method().get_class_name(), i.get_method().get_name(),
                                                  i.get_method().get_descriptor())
                    methodName = self.formatString(i.get_class_name(), i.get_name(), i.get_descriptor())

                    l.append(className)
                    l = list(set(l))
                    tem[methodName] = l

                if description in result:
                    result[description] = dict(result[description], **tem)
                else:
                    if tem:
                        result[description] = tem

        return result

    def get_api_string_string(self, d, x, string_string_list=STRING_STRING_LIST):
        """
        Return Type
            {
                DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                ...
            }
        """
        result = {}

        for string1, string2, description in string_string_list:
            l = []
            l1 = []
            l2 = []
            for s, _ in x.tainted_variables.get_strings():
                # if string1 == s.get_info():
                if re.compile(string1).search(s.get_info()):
                    for path1 in s.get_paths():
                        #access, idx = path[0]
                        mc1 = path1[1]
                        l1.append(mc1)
                    # if string2 == s.get_info():
                if re.compile(string2).search(s.get_info()):
                    for path2 in s.get_paths():
                        #access, idx = path[0]
                        mc2 = path2[1]
                        l2.append(mc2)

            tem = {}
            z = list(set(l1).intersection(set(l2)))
            if len(z) > 0:
                for i in z:
                    l.append(self.get_cm_method_format(d.get_cm_method(i)))
                    l = list(set(l))
                    keys = string1.strip('^$') + ' AND ' + string2.strip('^$')
                    tem[keys] = l

                if description in result:
                    result[description] = dict(result[description], **tem)
                else:
                    if tem:
                        result[description] = tem

        return result

    def get_api_method_string(self, d, x, method_string_dict=METHOD_STRING_DICT):
        """
        Return Type
            {
                DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                ...
            }
        """
        result = {}

        for (key, description_string), val in method_string_dict.iteritems():

            for s, _ in x.tainted_variables.get_strings():
                # print s.get_info()
                c = []
                # if key == s.get_info():
                if re.compile(key).search(s.get_info()):
                    for path in s.get_paths():
                        access, idx = path[0]
                        mc = path[1]
                        c.append(mc)

                    for class_name, list_method in val.iteritems():
                        for method_name, description_method in list_method:
                            m = []

                            results = x.tainted_packages.search_methods(class_name, method_name, ".")
                            for r in results:
                                m_idx = r.get_method().get_idx()
                                m.append(m_idx)

                            z = list(set(c).intersection(set(m)))
                            l = []
                            tem = {}
                            for i in z:
                                className = self.get_cm_method_format(d.get_cm_method(i))
                                description = description_method + description_string

                                l.append(className)
                                l = list(set(l))
                                tem[s.get_info()] = l

                                if description in result:
                                    result[description] = dict(result[description], **tem)
                                else:
                                    if tem:
                                        result[description] = tem

        return result

    def get_api_method_field(self, d, x, method_field_dict=METHOD_FIELD_DICT):
        """
        Return Type
            {
                DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                ...
            }
        """
        result = {}

        for (key, description_string), val in method_field_dict.iteritems():
            for s, _ in x.tainted_variables.get_fields():
                # print s.get_info()
                c = []
                # if key == s.get_info():
                if re.compile(key).search(s.get_info()[0]):
                    for path in s.get_paths():
                        access, idx = path[0]
                        mc = path[1]
                        c.append(mc)

                    for class_name, list_method in val.iteritems():
                        for method_name, description_method in list_method:
                            m = []

                            results = x.tainted_packages.search_methods(class_name, method_name, ".")
                            for r in results:
                                m_idx = r.get_method().get_idx()
                                m.append(m_idx)

                            z = list(set(c).intersection(set(m)))
                            l = []
                            tem = {}
                            description = description_method + description_string
                            for i in z:
                                className = self.get_cm_method_format(d.get_cm_method(i))
                                l.append(className)
                                l = list(set(l))
                                tem[s.get_info()[0]] = l

                            if description in result:
                                result[description] = dict(result[description], **tem)
                            else:
                                if tem:
                                    result[description] = tem

        return result

        # def get_string_url(self, d, x, url_list=URL_LIST):
        #     l = []
        #     dic = {}
        #
        #     for s, _ in x.tainted_variables.get_strings():
        #         for i in url_list:
        #             if i in s.get_info():
        #                 for path in s.get_paths():
        #                     access, idx = path[0]
        #                     m_idx = path[1]
        #                     #for a in path:
        #                     #    print a,"a"
        #                     #    access, idx = path[0]
        #                     #    m_idx = path[1]
        #                     l.append(self.get_cm_method_format(d.get_cm_method(m_idx)))
        #                     l = list(set(l))
        #                 dic[s.get_info()] = l
        #                 #print access, idx, m_idx,s.get_info(),self.get_cm_method_format(d.get_cm_method(m_idx))
        #             l = []
        #
        #     return dic

        # 旧算法
        # def get_api_method_field(self, x, method_field_dict=METHOD_FIELD_DICT):
        #     l = []
        #     c = []
        #     f = {}
        #
        #     for (i, description_string), val in method_field_dict.iteritems():
        #         for s, _ in x.tainted_variables.get_fields():
        #             if i == s.get_info()[0]:
        #                 for path in s.get_paths():
        #                     access, idx = path[0]
        #                     mc = path[1]
        #                     #print 'StringID:',mc,s.get_info()[0],'IN:',d.get_cm_method(mc)[0],d.get_cm_method(mc)[1]
        #                     c.append(mc)
        #
        #             for m_idx in c:
        #                 for class_name, list_method in val.iteritems():
        #                     for method_name, description_method in list_method:
        #                         results = x.tainted_packages.search_methods(class_name, method_name, ".")
        #                         for r in results:
        #                             className = self.formatString(r.get_method().get_class_name(),
        #                                                           r.get_method().get_name(),
        #                                                           r.get_method().get_descriptor())
        #                             methodName = self.formatString(r.get_class_name(), r.get_name(), r.get_descriptor())
        #                             description = description_method + description_string
        #                             if r.get_method().get_idx() == m_idx:
        #                                 #print description,r.get_method().get_idx(),r.get_method().get_class_name(),r.get_method().get_name()
        #                                 l.append(className)
        #                                 l = list(set(l))
        #                                 f[description] = {methodName: l}
        #             l = []
        #             c = []
        #     return f


class DEX:
    def __init__(self, filename):
        self.filename = filename

    def get_filename(self):
        return self.filename

    def get_filename_abs(self):
        filePath, filename = os.path.split(self.filename)
        # return filename[:-4].strip(" ")
        return filename[:-4]

    def get_filename_rel(self):
        s, f = os.path.splitext(self.filename)
        return s

    def get_file_path(self):
        filePath, filename = os.path.split(self.filename)
        return filePath

    def getLogPath(self):
        savePath, fileType = os.path.splitext(self.filename)
        return savePath.strip(" ") + ".txt"

    def get_md5(self):
        return md5(open(self.filename, "rb").read()).hexdigest()

    def get_sha1(self):
        return sha1(open(self.filename, "rb").read()).hexdigest()

    def get_digest(self):
        return b64encode(sha1(open(self.filename, "rb").read()).digest())

    def get_sha256(self):
        return sha256(open(self.filename, "rb").read()).hexdigest()

    def get_size(self):
        return str(os.path.getsize(self.filename))

    def getShDex(self):
        if SYS == "Darwin":
            cmd = "sh " + "\"" + TOOLS.dex2jar() + "\"" + " " + "\"" + \
                  self.filename + "\""
            try:
                os.system(cmd)
            except:
                pass
        if SYS == "Windows":
            cmd = TOOLS.dex2jar() + " \"" + self.filename + "\""
            try:
                os.system(cmd)
            except:
                pass

        open_cmd = TOOLS.jdGui() + " \"" + self.get_filename_rel() + "_dex2jar.jar" + "\""
        os.system(open_cmd)

    def getdexbaksmali(self):
        cmd = "java -jar \"" + TOOLS.baksmali() + "\" " + "\"" + self.filename + "\" -o \"" + os.path.join(
            self.get_file_path(), "Smali_" + self.get_filename_abs()) + "\""
        os.system(cmd)

    def get_cm_method_format(self, get_cm_method):
        return get_cm_method[0] + '->' + get_cm_method[1] + get_cm_method[2][0] + get_cm_method[2][1]

    def formatString(self, method, className, descriptor):
        return method + '->' + className + descriptor

    def get_detail_api(self, result):
        return get_detail_result(result)

    def get_all_api(self):
        d, x = AnalyzeDex(self.filename, raw=False)

        api_string = self.get_api_string(d, x)
        api_string_string = self.get_api_string_string(d, x)

        api_method = self.get_api_method(x)
        api_method_string = self.get_api_method_string(d, x)
        api_method_field = self.get_api_method_field(d, x)

        return [api_string, api_string_string, api_method, api_method_string, api_method_field]

    def get_api_string(self, d, x, string_list=STRING_LIST):
        """
        Return Type
            {
                DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                ...
            }
        """
        result = {}
        length = len(string_list)

        i = 0
        while i < length:
            key, description = string_list[i]
            tem = {}

            for s, _ in x.tainted_variables.get_strings():
                l = []
                # if key in s.get_info():
                if re.compile(key).search(s.get_info()):
                    for path in s.get_paths():
                        access, idx = path[0]
                        m_idx = path[1]
                        methodName = self.get_cm_method_format(d.get_cm_method(m_idx))
                        l.append(methodName)
                        l = list(set(l))
                    tem[s.get_info()] = l
            i += 1

            if description in result:
                result[description] = dict(result[description], **tem)
            else:
                if tem:
                    result[description] = tem

        return result

    def get_api_method(self, x, method_dict=METHOD_DICT):
        """
        Return Type
            {
                DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                ...
            }
        """
        result = {}

        for class_name, method_names in method_dict.iteritems():
            for method_name, description in method_names:
                l = []
                tem = {}
                results = x.tainted_packages.search_methods(class_name, method_name, ".")
                for i in results:
                    className = self.formatString(i.get_method().get_class_name(), i.get_method().get_name(),
                                                  i.get_method().get_descriptor())
                    methodName = self.formatString(i.get_class_name(), i.get_name(), i.get_descriptor())

                    l.append(className)
                    l = list(set(l))
                    tem[methodName] = l

                if description in result:
                    result[description] = dict(result[description], **tem)
                else:
                    if tem:
                        result[description] = tem

        return result

    def get_api_string_string(self, d, x, string_string_list=STRING_STRING_LIST):
        """
        Return Type
            {
                DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                ...
            }
        """
        result = {}

        for string1, string2, description in string_string_list:
            l = []
            l1 = []
            l2 = []
            for s, _ in x.tainted_variables.get_strings():
                # if string1 == s.get_info():
                if re.compile(string1).search(s.get_info()):
                    for path1 in s.get_paths():
                        #access, idx = path[0]
                        mc1 = path1[1]
                        l1.append(mc1)
                    # if string2 == s.get_info():
                if re.compile(string2).search(s.get_info()):
                    for path2 in s.get_paths():
                        #access, idx = path[0]
                        mc2 = path2[1]
                        l2.append(mc2)

            tem = {}
            z = list(set(l1).intersection(set(l2)))
            if len(z) > 0:
                for i in z:
                    l.append(self.get_cm_method_format(d.get_cm_method(i)))
                    l = list(set(l))
                    keys = string1.strip('^$') + ' AND ' + string2.strip('^$')
                    tem[keys] = l

                if description in result:
                    result[description] = dict(result[description], **tem)
                else:
                    if tem:
                        result[description] = tem

        return result

    def get_api_method_string(self, d, x, method_string_dict=METHOD_STRING_DICT):
        """
        Return Type
            {
                DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                ...
            }
        """
        result = {}

        for (key, description_string), val in method_string_dict.iteritems():

            for s, _ in x.tainted_variables.get_strings():
                # print s.get_info()
                c = []
                # if key == s.get_info():
                if re.compile(key).search(s.get_info()):
                    for path in s.get_paths():
                        access, idx = path[0]
                        mc = path[1]
                        c.append(mc)

                    for class_name, list_method in val.iteritems():
                        for method_name, description_method in list_method:
                            m = []

                            results = x.tainted_packages.search_methods(class_name, method_name, ".")
                            for r in results:
                                m_idx = r.get_method().get_idx()
                                m.append(m_idx)

                            z = list(set(c).intersection(set(m)))
                            l = []
                            tem = {}
                            for i in z:
                                className = self.get_cm_method_format(d.get_cm_method(i))
                                description = description_method + description_string

                                l.append(className)
                                l = list(set(l))
                                tem[s.get_info()] = l

                                if description in result:
                                    result[description] = dict(result[description], **tem)
                                else:
                                    if tem:
                                        result[description] = tem

        return result

    def get_api_method_field(self, d, x, method_field_dict=METHOD_FIELD_DICT):
        """
        Return Type
            {
                DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
                ...
            }
        """
        result = {}

        for (key, description_string), val in method_field_dict.iteritems():
            for s, _ in x.tainted_variables.get_fields():
                # print s.get_info()
                c = []
                # if key == s.get_info():
                if re.compile(key).search(s.get_info()[0]):
                    for path in s.get_paths():
                        access, idx = path[0]
                        mc = path[1]
                        c.append(mc)

                    for class_name, list_method in val.iteritems():
                        for method_name, description_method in list_method:
                            m = []

                            results = x.tainted_packages.search_methods(class_name, method_name, ".")
                            for r in results:
                                m_idx = r.get_method().get_idx()
                                m.append(m_idx)

                            z = list(set(c).intersection(set(m)))
                            l = []
                            tem = {}
                            description = description_method + description_string
                            for i in z:
                                className = self.get_cm_method_format(d.get_cm_method(i))
                                l.append(className)
                                l = list(set(l))
                                tem[s.get_info()[0]] = l

                            if description in result:
                                result[description] = dict(result[description], **tem)
                            else:
                                if tem:
                                    result[description] = tem

        return result


class AXML:
    def __init__(self, filename):
        self.filename = filename
        self.raw = open(filename, 'rb').read()
        self.xml = {}
        self.package = ""
        self.androidversion = {}
        self.permissions = []

        self.xml[filename] = minidom.parseString(apk.AXMLPrinter(self.raw).getBuff())
        self.package = self.xml[filename].documentElement.getAttribute("package")
        self.androidversion["Code"] = self.xml[filename].documentElement.getAttribute("android:versionCode")
        self.androidversion["Name"] = self.xml[filename].documentElement.getAttribute("android:versionName")

        for item in self.xml[filename].getElementsByTagName('uses-permission'):
            self.permissions.append(str(item.getAttribute("android:name")))

    def get_filename(self):
        return self.filename

    def get_filename_abs(self):
        filePath, filename = os.path.split(self.filename)
        # return filename[:-4].strip(" ")
        return filename[:-4]

    def get_filename_rel(self):
        s, f = os.path.splitext(self.filename)
        return s

    def get_file_path(self):
        filePath, filename = os.path.split(self.filename)
        return filePath

    def getLogPath(self):
        savePath, fileType = os.path.splitext(self.filename)
        return savePath.strip(" ") + ".txt"

    def get_md5(self):
        return md5(open(self.filename, "rb").read()).hexdigest()

    def get_sha1(self):
        return sha1(open(self.filename, "rb").read()).hexdigest()

    def get_digest(self):
        return b64encode(sha1(open(self.filename, "rb").read()).digest())

    def get_sha256(self):
        return sha256(open(self.filename, "rb").read()).hexdigest()

    def get_size(self):
        return str(os.path.getsize(self.filename))

    def get_package(self):
        return self.package

    def get_androidversion_name(self):
        return self.androidversion["Name"]

    def get_androidversion_code(self):
        return self.androidversion["Code"]

    def get_element(self, tag_name, attribute):
        """
            Return element in xml files which match with the tag name and the specific attribute

            @param tag_name : a string which specify the tag name
            @param attribute : a string which specify the attribute
        """
        for i in self.xml:
            for item in self.xml[i].getElementsByTagName(tag_name):
                value = item.getAttribute(attribute)

                if len(value) > 0:
                    return value
        return None

    def getMinSdkVersion(self):
        minSdk = self.get_element("uses-sdk", "android:minSdkVersion")
        if minSdk:
            try:
                return MIN_SDK_VERSION[minSdk]
            except KeyError:
                return minSdk
        else:
            return "None"

    def getPermission(self):
        for i in self.xml:
            x = []
            if not self.xml[i].getElementsByTagName('uses-permission'):
                return []
            else:
                for item in self.xml[i].getElementsByTagName('uses-permission'):
                    x.append(item.getAttribute("android:name"))

            if len(x) > 0:
                return x

    def getRiskPermission(self):
        x = []
        permission = self.getPermission()

        if len(permission) == 0:
            return ["该程序未发现含有权限"]
        else:
            for i in permission:
                try:
                    if RISK_PERMISSION[i] not in x:
                        x.append(RISK_PERMISSION[i])
                except KeyError:
                    pass

        if len(x) > 0:
            return x
        else:
            return ["该程序未发现含有风险权限"]

    def format_value(self, value):
        if len(value) > 0:
            if value[0] == ".":
                value = self.package + value
            else:
                v_dot = value.find(".")
                if v_dot == 0:
                    value = self.package + "." + value
                elif v_dot == -1:
                    value = self.package + "." + value
        return value

    def checkManifest(self):
        """
            1 有activity，但是程序没有入口
            2 有入口
            3 无图标
        """
        self.result = [self.filename]   # +
        self.result.append("1")
        # self.result = ["1"]

        for i in self.xml:
            if self.xml[i].getElementsByTagName("activity"):
                x = set()
                y = set()
                for item in self.xml[i].getElementsByTagName("activity"):
                    for sitem in item.getElementsByTagName("action"):
                        val = sitem.getAttribute("android:name")
                        if val == "android.intent.action.MAIN":
                            x.add(item.getAttribute("android:name"))

                    for sitem in item.getElementsByTagName("category"):
                        val = sitem.getAttribute("android:name")
                        if val == "android.intent.category.LAUNCHER":
                            y.add(item.getAttribute("android:name"))

                z = x.intersection(y)

                if len(z) > 0:
                    self.result[1] = "2"
                    # self.result[0] = "2"
                    self.result.append(self.format_value(z.pop()))
                    return self.result
                else:
                    self.result.append("0")
                    # self.result.append("0")
                    return self.result
            else:
                self.result[1] = "3"
                # self.result[0] = "3"
                self.result.append("0")
                return self.result

    def getDetailServices(self):
        """
            Return the detail of the services
            :rtype: dict
            {'name1': ['action1', 'action2', ...],
             'name2': ['action1', 'action2', ...], ...
            }
        """
        x = {}
        y = []

        for i in self.xml:
            for item in self.xml[i].getElementsByTagName("service"):
                val = self.format_value(item.getAttribute("android:name"))
                if not item.getElementsByTagName("action"):
                    y.append("None")
                    x[val] = y
                    y = []
                else:
                    for sitem in item.getElementsByTagName("action"):
                        a = sitem.getAttribute("android:name")
                        y.append(self.format_value(a))
                        x[val] = y
                    y = []

        if x:
            return x
        else:
            return "None"

    def getDetailReceivers(self):
        """
            Return the detail of the receivers
            :rtype: dict
            {'name1': ['action1,Priority1', 'action2,Priority2', ...],
             'name2': ['action1,Priority1', 'action2,Priority2', ...], ...
            }

        """
        x = {}
        y = []

        for i in self.xml:
            for item in self.xml[i].getElementsByTagName("receiver"):
                val = self.format_value(item.getAttribute("android:name"))
                if not item.getElementsByTagName("action"):
                    # y.append("None,None")
                    y.append(["None", "None"])
                    x[val] = y
                    y = []
                else:
                    for sitem in item.getElementsByTagName("action"):
                        a = sitem.getAttribute("android:name")
                        p = sitem.parentNode.getAttribute("android:priority")
                        if not p:
                            p = "None"
                            # y.append(self.format_value(a) + "," + p)
                        y.append([self.format_value(a), p])
                        x[val] = y
                    y = []

        if x:
            return x
        else:
            return "None"

    def get_xml(self):
        return apk.AXMLPrinter(self.raw).get_xml()


class CSN:
    def __init__(self, filename):
        self.filename = filename
        self.raw = open(filename, 'rb').read()
        self.success, self.cert = self.get_obj_certificate()

    def get_filename(self):
        return self.filename

    def get_filename_abs(self):
        filePath, filename = os.path.split(self.filename)
        # return filename[:-4].strip(" ")
        return filename[:-4]

    def get_filename_rel(self):
        s, f = os.path.splitext(self.filename)
        return s

    def get_file_path(self):
        filePath, filename = os.path.split(self.filename)
        return filePath

    def getLogPath(self):
        savePath, fileType = os.path.splitext(self.filename)
        return savePath.strip(" ") + ".txt"

    def get_md5(self):
        return md5(open(self.filename, "rb").read()).hexdigest()

    def get_sha1(self):
        return sha1(open(self.filename, "rb").read()).hexdigest()

    def get_digest(self):
        return b64encode(sha1(open(self.filename, "rb").read()).digest())

    def get_sha256(self):
        return sha256(open(self.filename, "rb").read()).hexdigest()

    def get_size(self):
        return str(os.path.getsize(self.filename))

    def get_obj_certificate(self):
        cert = chilkat.CkCert()
        f = self.raw
        bytedata = chilkat.CkByteData()
        bytedata.append2(f, len(f))
        success = cert.LoadFromBinary(bytedata)

        return success, cert

    def getCertificateSN(self):
        success, cert = self.get_obj_certificate()

        if self.success:
            x = []
            c = self.cert.serialNumber()
            for i in c:
                x.append(i)

            if x[0] == x[1] == '0':
                x = x[2:]
                return ''.join(x).lower()
            else:
                return ''.join(x).lower()

    def getCertificateIDN(self):
        if self.success:
            return 'C=' + self.cert.issuerC() + ', CN=' + self.cert.issuerCN() + ', DN=' + self.cert.issuerDN() + \
                   ', E=' + self.cert.issuerE() + ', L=' + self.cert.issuerL() + ', O=' + self.cert.issuerO() + \
                   ', OU=' + self.cert.issuerOU() + ', S=' + self.cert.issuerS()
        else:
            return None

    def getCertificateSDN(self):
        if self.success:
            return 'C=' + self.cert.subjectC() + ', CN=' + self.cert.subjectCN() + ', DN=' + self.cert.subjectDN() + \
                   ', E=' + self.cert.subjectE() + ', L=' + self.cert.subjectL() + ', O=' + self.cert.subjectO() + \
                   ', OU=' + self.cert.subjectOU() + ', S=' + self.cert.subjectS()
        else:
            return None

    def check_black_csn(self, csn, black_list_csn=BLACK_LIST_CSN):
        for k, v in black_list_csn:
            if k == csn:
                return v


def get_intersection_list(list1, list2):
    """
        set1 = ['1','12','2']
        set2 = ['1']
        return ['1','12']
    """
    l = []
    for i in list1:
        for j in list2:
            if i.startswith(j):
                l.append(i)
    return l


def get_complement_list(list1, list2):
    """
        set1 = ['1','12','2']
        set2 = ['1']
        return ['2']
    """
    l = []
    for i in list1:
        for j in list2:
            if not i.startswith(j):
                l.append(i)
    return l


def AnalyzeAPK(filename, raw=False, decompiler=None):
    a = APK(filename, raw)

    d, dx = AnalyzeDex(a.get_dex(), raw=True)

    return a, d, dx


def AnalyzeDex(filename, raw=False):
    """
        Analyze an android dex file and setup all stuff for a more quickly analysis !

        @param filename : the filename of the android dex file or a buffer which represents the dex file
        @param raw : True is you would like to use a buffer

        @rtype : return the DalvikVMFormat, and VMAnalysis objects
    """
    # DalvikVMFormat
    d = None
    if raw == False:
        d = DalvikVMFormat(open(filename, "rb").read())
    else:
        d = DalvikVMFormat(filename)

    # EXPORT VM to python namespace
    #ExportVMToPython( d )

    # VMAnalysis
    dx = VMAnalysis(d)
    #dx = uVMAnalysis( d )

    d.set_vmanalysis(dx)

    return d, dx


def get_detail_result(result, white_list=WHITE_LIST_PATH):
    """
        white_list_result RETURN TYPE:
        {
            'DESWL1': [{DES1: {KEY: [V1, V2, ...]}, {DES2: {KEY: [V1, V2, ...]}, ...],
            'DESWL2': [{DES1: {KEY: [V1, V2, ...]}, {DES2: {KEY: [V1, V2, ...]}, ...],
            ...
        }
        result RETURN TYPE:
        {
            DES1:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
            DES2:{KEY1:[V1, V2, ...], KEY2:[V1, V2, ...], ...},
            ...
        }
    """
    white_list_result = {}
    if result:

        white_list_length = len(white_list)
        w = 0
        while w < white_list_length:
            key = white_list[w][0]
            white_list_description = white_list[w][1]

            white_list_tem_result_dict = {}
            white_list_tem_result_list = []
            for (description, dicts) in result.iteritems():
                white_list_tem_dict = {}
                for (k, lists) in dicts.iteritems():

                    white_list_tem_list = []
                    lists_length = len(lists)
                    l = 0
                    while l < lists_length:
                        if re.compile(key).search(lists[l]):
                            white_list_tem_list.append(lists[l])

                            lists.pop(l)
                            lists_length -= 1

                        else:
                            l += 1

                    if white_list_tem_list:
                        white_list_tem_dict[k] = white_list_tem_list
                    if white_list_tem_dict:
                        white_list_tem_result_dict[description] = white_list_tem_dict

            if white_list_tem_result_dict:
                white_list_tem_result_list.append(white_list_tem_result_dict)
            w += 1

            if white_list_description in white_list_result:
                for j in white_list_tem_result_list:
                    white_list_result[white_list_description].append(j)
            else:
                if white_list_tem_result_list:
                    white_list_result[white_list_description] = white_list_tem_result_list

        for ks in result.keys():
            for ds in result[ks].keys():
                if not result[ks][ds]:
                    del (result[ks][ds])
            if not result[ks]:
                del (result[ks])

    return [result, white_list_result]


import urllib
import urllib2
import random
import json
from configure import VIRUSTOTAL_APIKEY

url = "https://www.virustotal.com/vtapi/v2/file/report"


def get_json(resource, api_key):
    parameters = dict(resource=resource, apikey=api_key)
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    try:
        response = urllib2.urlopen(req)
        json = response.read()
        return json
    except urllib2.HTTPError, e:
        print e


def vt_hash(resource):
    api_key = random.sample(VIRUSTOTAL_APIKEY, 1)[0]
    return get_json(resource, api_key)


def vt_hash_result(resource):
    """
        return json type
    """
    try:
        return json.loads(vt_hash(resource))
    except:
        return None


def vt_hash_result_show(resource):
    """
        scan_date 扫描时间
        permalink 链接
        total 总计
        positives 报毒数量
        scans 详情
    """

    response_dict = vt_hash_result(resource)
    if response_dict and response_dict['response_code']:
        print 'Detection ratio:', str(response_dict['positives']) + '/' + str(response_dict['total'])
        print 'Analysis date:', response_dict['scan_date']
        #print 'Permalink:', response_dict['permalink']
        print 'Detail'

        l = []
        r = []
        t = []
        for (k, v) in response_dict['scans'].items():
            #print v
            if v.get("detected"):
                l.append(len(k))
                r.append(len(v.get("result")))
                t.append(len(v.get("update")))

            else:
                pass
        k_width = max(l)
        r_width = max(r)
        t_width = max(t)

        print '+' + '-' * k_width + '+' + '-' * r_width + '+' + '-' * t_width + '+'
        for (k, v) in response_dict['scans'].items():
            if v.get("detected"):
                print '|' + str(k) + ' ' * (k_width - len(k)) + '|' + str(v.get("result")) + ' ' * (
                    r_width - len(str(v.get("result")))) + '|' + str(v.get("update")) + ' ' * (
                          t_width - len(str(v.get("update")))) + '|'
                print '+' + '-' * k_width + '+' + '-' * r_width + '+' + '-' * t_width + '+'
            else:
                pass
    else:
        print "Not found!"