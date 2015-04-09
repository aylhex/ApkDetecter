#-*- coding:utf-8-*-
__author__ = 'Andy'

from androguard.core import bytecode
from androguard.core.bytecode import SV

ATTRIBUTE_IX_NAMESPACE_URI = 0
ATTRIBUTE_IX_NAME = 1
ATTRIBUTE_IX_VALUE_STRING = 2
ATTRIBUTE_IX_VALUE_TYPE = 3
ATTRIBUTE_IX_VALUE_DATA = 4
ATTRIBUTE_LENGHT = 5

CHUNK_AXML_FILE = 0x00080003
CHUNK_RESOURCEIDS = 0x00080180
CHUNK_XML_FIRST = 0x00100100
CHUNK_XML_START_NAMESPACE = 0x00100100
CHUNK_XML_END_NAMESPACE = 0x00100101
CHUNK_XML_START_TAG = 0x00100102
CHUNK_XML_END_TAG = 0x00100103
CHUNK_XML_TEXT = 0x00100104
CHUNK_XML_LAST = 0x00100104

TYPE_STRING = 3

START_DOCUMENT = 0
END_DOCUMENT = 1
START_TAG = 2
END_TAG = 3
TEXT = 4



class AXMLParser:
    def __init__(self, raw_buff):
        self.reset()

        self.buff = bytecode.BuffHandle(raw_buff)

        self.buff.read(4)
        self.buff.read(4)

        self.sb = StringBlock(self.buff)

        self.m_resourceIDs = []
        self.m_prefixuri = {}
        self.m_uriprefix = {}
        self.m_prefixuriL = []

    def reset(self):
        self.m_event = -1
        self.m_lineNumber = -1
        self.m_name = -1
        self.m_namespaceUri = -1
        self.m_attributes = []
        self.m_idAttribute = -1
        self.m_classAttribute = -1
        self.m_styleAttribute = -1

    def next(self):
        self.doNext()
        return self.m_event

    def doNext(self):
        if self.m_event == END_DOCUMENT:
            return

        event = self.m_event

        self.reset()
        while 1:
            chunkType = -1

            # Fake END_DOCUMENT event.
            if event == END_TAG:
                pass

            # START_DOCUMENT
            if event == START_DOCUMENT:
                chunkType = CHUNK_XML_START_TAG
            else:
                if self.buff.end() == True:
                    self.m_event = END_DOCUMENT
                    break
                chunkType = SV('<L', self.buff.read(4)).get_value()

            if chunkType == CHUNK_RESOURCEIDS:
                chunkSize = SV('<L', self.buff.read(4)).get_value()
                # FIXME
                if chunkSize < 8 or chunkSize % 4 != 0:
                    raise ("ooo")

                for i in range(0, chunkSize / 4 - 2):
                    self.m_resourceIDs.append(SV('<L', self.buff.read(4)))

                continue

            # FIXME
            if chunkType < CHUNK_XML_FIRST or chunkType > CHUNK_XML_LAST:
                raise ("ooo")

            # Fake START_DOCUMENT event.
            if chunkType == CHUNK_XML_START_TAG and event == -1:
                self.m_event = START_DOCUMENT
                break

            self.buff.read(4) #/*chunkSize*/
            lineNumber = SV('<L', self.buff.read(4)).get_value()
            self.buff.read(4) #0xFFFFFFFF

            if chunkType == CHUNK_XML_START_NAMESPACE or chunkType == CHUNK_XML_END_NAMESPACE:
                if chunkType == CHUNK_XML_START_NAMESPACE:
                    prefix = SV('<L', self.buff.read(4)).get_value()
                    uri = SV('<L', self.buff.read(4)).get_value()

                    self.m_prefixuri[prefix] = uri
                    self.m_uriprefix[uri] = prefix
                    self.m_prefixuriL.append((prefix, uri))
                else:
                    self.buff.read(4)
                    self.buff.read(4)
                    (prefix, uri) = self.m_prefixuriL.pop()
                    #del self.m_prefixuri[ prefix ]
                    #del self.m_uriprefix[ uri ]

                continue

            self.m_lineNumber = lineNumber

            if chunkType == CHUNK_XML_START_TAG:
                self.m_namespaceUri = SV('<L', self.buff.read(4)).get_value()
                self.m_name = SV('<L', self.buff.read(4)).get_value()

                # FIXME
                self.buff.read(4) #flags

                attributeCount = SV('<L', self.buff.read(4)).get_value()
                self.m_idAttribute = (attributeCount >> 16) - 1
                attributeCount = attributeCount & 0xFFFF
                self.m_classAttribute = SV('<L', self.buff.read(4)).get_value()
                self.m_styleAttribute = (self.m_classAttribute >> 16) - 1

                self.m_classAttribute = (self.m_classAttribute & 0xFFFF) - 1

                for i in range(0, attributeCount * ATTRIBUTE_LENGHT):
                    self.m_attributes.append(SV('<L', self.buff.read(4)).get_value())

                for i in range(ATTRIBUTE_IX_VALUE_TYPE, len(self.m_attributes), ATTRIBUTE_LENGHT):
                    self.m_attributes[i] = (self.m_attributes[i] >> 24)

                self.m_event = START_TAG
                break

            if chunkType == CHUNK_XML_END_TAG:
                self.m_namespaceUri = SV('<L', self.buff.read(4)).get_value()
                self.m_name = SV('<L', self.buff.read(4)).get_value()
                self.m_event = END_TAG
                break

            if chunkType == CHUNK_XML_TEXT:
                self.m_name = SV('<L', self.buff.read(4)).get_value()

                # FIXME
                self.buff.read(4) #?
                self.buff.read(4) #?

                self.m_event = TEXT
                break

    def getPrefixByUri(self, uri):
        try:
            return self.m_uriprefix[uri]
        except KeyError:
            return -1

    def getPrefix(self):
        try:
            return self.sb.getRaw(self.m_prefixuri[self.m_namespaceUri])
        except KeyError:
            return ""

    def getName(self):
        if self.m_name == -1 or (self.m_event != START_TAG and self.m_event != END_TAG):
            return ""

        return self.sb.getRaw(self.m_name)

    def getText(self):
        if self.m_name == -1 or self.m_event != TEXT:
            return ""

        return self.sb.getRaw(self.m_name)

    def getNamespacePrefix(self, pos):
        prefix = self.m_prefixuriL[pos][0]
        return self.sb.getRaw(prefix)

    def getNamespaceUri(self, pos):
        uri = self.m_prefixuriL[pos][1]
        return self.sb.getRaw(uri)

    def getXMLNS(self):
        buff = ""

        i = 0
        while 1:
            try:
                buff += "xmlns:%s=\"%s\"\n" % ( self.getNamespacePrefix(i), self.getNamespaceUri(i) )
            except IndexError:
                break

            i += 1

        return buff

    def getNamespaceCount(self, pos):
        pass

    def getAttributeOffset(self, index):
        # FIXME
        if self.m_event != START_TAG:
            raise ("Current event is not START_TAG.")

        offset = index * 5
        # FIXME
        if offset >= len(self.m_attributes):
            raise ("Invalid attribute index")

        return offset

    def getAttributeCount(self):
        if self.m_event != START_TAG:
            return -1

        return len(self.m_attributes) / ATTRIBUTE_LENGHT

    def getAttributePrefix(self, index):
        offset = self.getAttributeOffset(index)
        uri = self.m_attributes[offset + ATTRIBUTE_IX_NAMESPACE_URI]

        prefix = self.getPrefixByUri(uri)
        if prefix == -1:
            return ""

        return self.sb.getRaw(prefix)

    def getAttributeName(self, index):
        offset = self.getAttributeOffset(index)
        name = self.m_attributes[offset + ATTRIBUTE_IX_NAME]

        if name == -1:
            return ""

        return self.sb.getRaw(name)

    def getAttributeValueType(self, index):
        offset = self.getAttributeOffset(index)
        return self.m_attributes[offset + ATTRIBUTE_IX_VALUE_TYPE]

    def getAttributeValueData(self, index):
        offset = self.getAttributeOffset(index)
        return self.m_attributes[offset + ATTRIBUTE_IX_VALUE_DATA]

    def getAttributeValue(self, index):
        offset = self.getAttributeOffset(index)
        valueType = self.m_attributes[offset + ATTRIBUTE_IX_VALUE_TYPE]
        if valueType == TYPE_STRING:
            valueString = self.m_attributes[offset + ATTRIBUTE_IX_VALUE_STRING]
            return self.sb.getRaw(valueString)
            # WIP
        return ""
        #int valueData=m_attributes[offset+ATTRIBUTE_IX_VALUE_DATA];
        #return TypedValue.coerceToString(valueType,valueData);

######################################################## AXML FORMAT ########################################################
# Translated from http://code.google.com/p/android4me/source/browse/src/android/content/res/AXmlResourceParser.java
class StringBlock:
    def __init__(self, buff):
        buff.read(4)

        self.chunkSize = SV('<L', buff.read(4))
        self.stringCount = SV('<L', buff.read(4))
        self.styleOffsetCount = SV('<L', buff.read(4))

        # unused value ?
        buff.read(4) # ?

        self.stringsOffset = SV('<L', buff.read(4))
        self.stylesOffset = SV('<L', buff.read(4))

        self.m_stringOffsets = []
        self.m_styleOffsets = []
        self.m_strings = []
        self.m_styles = []

        for i in range(0, self.stringCount.get_value()):
            self.m_stringOffsets.append(SV('<L', buff.read(4)))

        for i in range(0, self.styleOffsetCount.get_value()):
            self.m_stylesOffsets.append(SV('<L', buff.read(4)))

        size = self.chunkSize.get_value() - self.stringsOffset.get_value()
        if self.stylesOffset.get_value() != 0:
            size = self.stylesOffset.get_value() - self.stringsOffset.get_value()

        # FIXME
        if (size % 4) != 0:
            pass

        for i in range(0, size / 4):
            self.m_strings.append(SV('=L', buff.read(4)))

        if self.stylesOffset.get_value() != 0:
            size = self.chunkSize.get_value() - self.stringsOffset.get_value()

            # FIXME
            if (size % 4) != 0:
                pass

            for i in range(0, size / 4):
                self.m_styles.append(SV('=L', buff.read(4)))

    def getRaw(self, idx):
        if idx < 0 or self.m_stringOffsets == [] or idx >= len(self.m_stringOffsets):
            return None

        offset = self.m_stringOffsets[idx].get_value()
        length = self.getShort(self.m_strings, offset)

        data = ""

        while length > 0:
            offset += 2
            # Unicode character
            data += unichr(self.getShort(self.m_strings, offset))

            # FIXME
            if data[-1] == "&":
                data = data[:-1]

            length -= 1

        return data

    def getShort(self, array, offset):
        value = array[offset / 4].get_value()
        if ((offset % 4) / 2) == 0:
            return value & 0xFFFF
        else:
            return value >> 16
