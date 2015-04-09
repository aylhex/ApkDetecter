#-*- coding:utf-8-*-
__author__ = 'Andy'
import os
from hashlib import md5, sha1, sha256
from base64 import b64encode
from core.chilkatCert.win32 import chilkat

BLACK_LIST_CSN = [
    ('936eacbe07f201df', 'Google测试证书(打包党)'),
    ('4f33fcd6',         'a.risk.zhigao')]

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

    # def getCertificateIDN(self):
    #     if self.success:
    #         return 'C=' + self.cert.issuerC() + ', CN=' + self.cert.issuerCN() + ', DN=' + self.cert.issuerDN() + \
    #                ', E=' + self.cert.issuerE() + ', L=' + self.cert.issuerL() + ', O=' + self.cert.issuerO() + \
    #                ', OU=' + self.cert.issuerOU() + ', S=' + self.cert.issuerS()
    #     else:
    #         return None

    def getCertificateIDN(self):
        if self.success:
            return 'C=' + str(self.cert.issuerC()) + ', CN=' + str(self.cert.issuerCN() + ', DN=' + str(self.cert.issuerDN()) + \
                   ', E=' + str(self.cert.issuerE()) + ', L=' + str(self.cert.issuerL()) + ', O=') + str(self.cert.issuerO()) + \
                   ', OU=' + str(self.cert.issuerOU()) + ', S=' + str(self.cert.issuerS())
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

