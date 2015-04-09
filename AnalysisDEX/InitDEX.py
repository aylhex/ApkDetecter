__author__ = 'Andy'

class InitDEX():

    def __init__(self):
         self.dexheader = {
                    "header_magic": u"",
                    "header_checksum": u"",
                    "header_signature": u"",
                    "header_fileSize": u"",
                    "header_headerSize": u"",
                    "header_endianTag": u"",
                    "header_linkSize": u"",
                    "header_linkOff": u"",
                    "header_mapOff": u"",
                    "header_stringIdsSize": u"",
                    "header_stringIdsOff": u"",
                    "header_typeIdsSize": u"",
                    "header_typeIdsOff": u"",
                    "header_protoIdsSize": u"",
                    "header_protoIdsOff": u"",
                    "header_fieldIdsSize": u"",
                    "header_fieldIdsOff": u"",
                    "header_methodIdsSize": u"",
                    "header_methodIdsOff": u"",
                    "header_classDefsSize": u"",
                    "header_classDefsOff": u"",
                    "header_dataSize": u"",
                    "header_dataOff": u""}

    def getDexInfo(self, path):

        self.dexheader.clear()
        infile = file(path, "rb")

        infile.seek(0, 1)
        byte = infile.read(8)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_magic"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_checksum"] = hexstr.upper()

        byte = infile.read(20)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_signature"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_fileSize"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_headerSize"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_endianTag"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_linkSize"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_linkOff"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_mapOff"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_stringIdsSize"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_stringIdsOff"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_typeIdsSize"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_typeIdsOff"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_protoIdsSize"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_protoIdsOff"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_fieldIdsSize"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_fieldIdsOff"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_methodIdsSize"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_methodIdsOff"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_classDefsSize"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_classDefsOff"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_dataSize"] = hexstr.upper()

        byte = infile.read(4)
        hexstr = "%s" % byte.encode('hex')
        self.dexheader["header_dataOff"] = hexstr.upper()

        infile.close()
        return self.dexheader




if __name__ == "__main__":
    obj = InitDEX()
    obj.getDexInfo()
