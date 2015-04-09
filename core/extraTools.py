# -*- coding:utf-8 -*-
from sys import argv
from os import path, walk
from platform import system

SYS = system()


class myTools():
    extraLib = path.join(path.split(argv[0])[0], 'ExtraLib')

    def __int__(self, extraLib):
        self.extraLib = extraLib

    def getFile(self, OPT):
        for parent, dirNames, fileNames in walk(self.extraLib):
            for fileName in fileNames:
                if fileName == OPT:
                    return path.join(parent, fileName)

    #def cert(self):
    #    return self.getFile('cert.jar')
    #
    #def certSN(self):
    #    return self.getFile('certSN.jar')
    #
    #def certIDN(self):
    #    return self.getFile('certIDN.jar')
    #
    #def certSDN(self):
    #    return self.getFile('certSDN.jar')

    def apkTool(self):
        return self.getFile('apktool.jar')

    def dex2jar(self):
        if SYS == "Darwin":
            return self.getFile('dex2jar.sh')
        if SYS == "Windows":
            return self.getFile('dex2jar.bat')

    def jdGui(self):
        if SYS == "Darwin":
            return self.getFile('jd-gui')
        if SYS == "Windows":
            return self.getFile('jd-gui.exe')

    def smali(self):
        return self.getFile('smali.jar')

    def baksmali(self):
        return self.getFile('baksmali.jar')

    def SSS(self):
        return self.getFile('SimpleShellSystem.jar')

    def parser(self):
        return self.getFile('parser.js')

    #def temp(self):
    #    return path.join(path.split(argv[0])[0], 'temp')