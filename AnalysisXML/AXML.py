#-*- coding:utf-8-*-
__author__ = 'Andy'
import os
from hashlib import md5, sha1, sha256
from base64 import b64encode
from xml.dom import minidom
from AXMLPrinter import AXMLPrinter

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

class AXML:
    def __init__(self, filename):
        self.filename = filename
        self.raw = open(filename, 'rb').read()
        self.xml = {}
        self.package = ""
        self.androidversion = {}
        self.permissions = []

        self.xml[filename] = minidom.parseString(AXMLPrinter(self.raw).getBuff())
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
        #print AXMLPrinter(self.raw).get_xml()
        return AXMLPrinter(self.raw).get_xml()
