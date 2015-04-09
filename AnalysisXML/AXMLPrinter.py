#-*- coding:utf-8-*-
__author__ = 'Andy'

from struct import pack, unpack
from xml.dom import minidom
from xml.sax.saxutils import escape

from AXMLParser import AXMLParser
from androguard.core import androconf


TYPE_ATTRIBUTE = 2
TYPE_DIMENSION = 5
TYPE_FIRST_COLOR_INT = 28
TYPE_FIRST_INT = 16
TYPE_FLOAT = 4
TYPE_FRACTION = 6
TYPE_INT_BOOLEAN = 18
TYPE_INT_COLOR_ARGB4 = 30
TYPE_INT_COLOR_ARGB8 = 28
TYPE_INT_COLOR_RGB4 = 31
TYPE_INT_COLOR_RGB8 = 29
TYPE_INT_DEC = 16
TYPE_INT_HEX = 17
TYPE_LAST_COLOR_INT = 31
TYPE_LAST_INT = 31
TYPE_NULL = 0
TYPE_REFERENCE = 1
TYPE_STRING = 3

START_DOCUMENT = 0
END_DOCUMENT = 1
START_TAG = 2
END_TAG = 3
TEXT = 4

RADIX_MULTS = [0.00390625, 3.051758E-005, 1.192093E-007, 4.656613E-010]
DIMENSION_UNITS = ["px", "dip", "sp", "pt", "in", "mm", "", ""]
FRACTION_UNITS = ["%", "%p", "", "", "", "", "", ""]

COMPLEX_UNIT_MASK = 15
class AXMLPrinter:
    def __init__(self, raw_buff):
        self.axml = AXMLParser(raw_buff)
        self.xmlns = False

        self.buff = ""

        while 1:
            _type = self.axml.next()
            # print "tagtype = ", _type

            if _type == START_DOCUMENT:
                self.buff += "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            elif _type == START_TAG:
                self.buff += "<%s%s\n" % ( self.getPrefix(self.axml.getPrefix()), self.axml.getName() )

                # FIXME : use namespace
                if self.xmlns == False:
                    self.buff += self.axml.getXMLNS()
                    self.xmlns = True

                for i in range(0, self.axml.getAttributeCount()):
                    self.buff += "%s%s=\"%s\"\n" % ( self.getPrefix(
                        self.axml.getAttributePrefix(i)), self.axml.getAttributeName(i),
                                                     self._escape(self.getAttributeValue(i)) )

                self.buff += ">\n"

            elif _type == END_TAG:
                self.buff += "</%s%s>\n" % ( self.getPrefix(self.axml.getPrefix()), self.axml.getName() )

            elif _type == TEXT:
                self.buff += "%s\n" % self.axml.getText()

            elif _type == END_DOCUMENT:
                break

    # pleed patch
    def _escape(self, s):
        s = s.replace("&", "&amp;")
        s = s.replace('"', "&quot;")
        s = s.replace("'", "&apos;")
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")

        return escape(s)


    def getBuff(self):
        return self.buff.encode("utf-8")

    def get_xml(self):
        # print self.getBuff()toprettyxml
        return minidom.parseString(self.getBuff()).toprettyxml(indent="  ", newl="", encoding = 'utf-8')
        # return minidom.parseString(self.getBuff()).toxml(encoding = 'utf-8')

    def getPrefix(self, prefix):
        if prefix == None or len(prefix) == 0:
            return ""

        return prefix + ":"

    def getAttributeValue(self, index):
        _type = self.axml.getAttributeValueType(index)
        _data = self.axml.getAttributeValueData(index)

        #print _type, _data
        if _type == TYPE_STRING:
            return self.axml.getAttributeValue(index)

        elif _type == TYPE_ATTRIBUTE:
            return "?%s%08X" % (self.getPackage(_data), _data)

        elif _type == TYPE_REFERENCE:
            return "@%s%08X" % (self.getPackage(_data), _data)

        # WIP
        elif _type == TYPE_FLOAT:
            return "%f" % unpack("=f", pack("=L", _data))[0]

        elif _type == TYPE_INT_HEX:
            return "0x%08X" % _data

        elif _type == TYPE_INT_BOOLEAN:
            if _data == 0:
                return "false"
            return "true"

        elif _type == TYPE_DIMENSION:
            return "%f%s" % (self.complexToFloat(_data), DIMENSION_UNITS[_data & COMPLEX_UNIT_MASK])

        elif _type == TYPE_FRACTION:
            return "%f%s" % (self.complexToFloat(_data), FRACTION_UNITS[_data & COMPLEX_UNIT_MASK])

        elif _type >= TYPE_FIRST_COLOR_INT and _type <= TYPE_LAST_COLOR_INT:
            return "#%08X" % _data

        elif _type >= TYPE_FIRST_INT and _type <= TYPE_LAST_INT:
            return "%d" % androconf.long2int(_data)

        return "<0x%X, type 0x%02X>" % (_data, _type)

    def complexToFloat(self, xcomplex):
        return (float)(xcomplex & 0xFFFFFF00) * RADIX_MULTS[(xcomplex >> 4) & 3];

    def getPackage(self, id):
        if id >> 24 == 1:
            return "android:"
        return ""