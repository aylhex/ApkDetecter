#-*- coding:utf-8-*-
__author__ = 'Andy'
from AnalysisCSN.CSN import CSN

class AnCSN():
    def csnAnalysis(self, a_file):
        global log
        csn = CSN(a_file)

        ######################################################## 基本信息 ###############################################
        print "文件路径: ", csn.get_filename()
        print "序列号: ", csn.getCertificateSN()
        print "发行者: ", csn.getCertificateIDN()
        print "签发人: ", csn.getCertificateSDN()
        print "文件大小: ", csn.get_size() + " 字节"
        print "CSNMd5: ", csn.get_md5()
        print "CSNDigest: ", csn.get_digest()
        print "CSNSha1: ", csn.get_sha1()
        print "CSNSha256: ", csn.get_sha256()

        ######################################################## 黑名单证书 ############################################
        result_csn = csn.check_black_csn(csn.getCertificateSN())
        if result_csn:
            print "-" * 55, ""
            print "黑名单证书: ", '是 ' + result_csn
        else:
            pass
        print "-" * 55, ""
        raw_input('Done!')
        log.close()

if __name__ == "__main__":
    obj = AnCSN()
    path = r"d:\sample_tx\9.09\e7fea6a5abdaf57b131d6e1fb30a7e49\META-INF\CERT.RSA"
    obj.csnAnalysis(path)