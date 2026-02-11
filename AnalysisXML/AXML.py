# -*- coding: utf-8 -*-
__author__ = 'Andy'

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
    "18": "Android 4.3",
    "19": "Android 4.4",
    "20": "Android 4.4W",
    "21": "Android 5.0",
    "22": "Android 5.1",
    "23": "Android 6.0",
    "24": "Android 7.0",
    "25": "Android 7.1",
    "26": "Android 8.0",
    "27": "Android 8.1",
    "28": "Android 9",
    "29": "Android 10",
    "30": "Android 11",
    "31": "Android 12",
    "32": "Android 12L",
    "33": "Android 13",
    "34": "Android 14",
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
    def __init__(self, apk_obj):
        self.apk = apk_obj

    def get_package(self):
        return self.apk.get_package()

    def get_androidversion_name(self):
        return self.apk.get_androidversion_name()

    def get_androidversion_code(self):
        return self.apk.get_androidversion_code()

    def getMinSdkVersion(self):
        min_sdk = self.apk.get_min_sdk_version()
        if min_sdk:
            return MIN_SDK_VERSION.get(str(min_sdk), str(min_sdk))
        return "None"

    def getRiskPermission(self):
        permissions = self.apk.get_permissions()
        risk_perms = []
        if not permissions:
            return ["该程序未发现含有权限"]
        
        for p in permissions:
            if p in RISK_PERMISSION:
                desc = RISK_PERMISSION[p]
                if desc not in risk_perms:
                    risk_perms.append(desc)
        
        if risk_perms:
            return risk_perms
        else:
            return ["该程序未发现含有风险权限"]
