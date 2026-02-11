# -*- coding: utf-8 -*-
__author__ = 'Andy'

class CSN:
    def __init__(self, apk_obj):
        self.apk = apk_obj
        self.certs = []
        try:
            # androguard 3.3.5+ returns x509 objects
            self.certs = list(self.apk.get_certificates())
        except Exception as e:
            print(f"Error getting certificates: {e}")
        
        self.cert = self.certs[0] if self.certs else None

    def get_size(self):
        try:
            for f in self.apk.get_files():
                if f.endswith('.RSA') or f.endswith('.DSA') or f.endswith('.EC'):
                     # get_file returns bytes
                     return str(len(self.apk.get_file(f)))
        except:
            pass
        return "0"

    def getCertificateSN(self):
        if not self.cert: return ""
        try:
            return format(self.cert.serial_number, 'x').lower()
        except:
            return ""

    def getCertificateIDN(self):
        if not self.cert: return ""
        try:
            # Use rfc4514_string for standard string representation
            # It returns comma separated values like CN=Name,C=US
            return self.cert.issuer.rfc4514_string()
        except:
            return str(self.cert.issuer)

    def getCertificateSDN(self):
        if not self.cert: return ""
        try:
            return self.cert.subject.rfc4514_string()
        except:
            return str(self.cert.subject)
