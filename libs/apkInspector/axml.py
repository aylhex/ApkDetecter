import io
import logging
import struct
import random

from .extract import extract_file_based_on_header_info
from .headers import ZipEntry
from .helpers import escape_xml_entities

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d -> %(funcName)s : %(message)s'
)


class ResChunkHeader:
    """
    Chunk header used throughout the axml.
    This header is essential as it contains information about the header size but also the total size of the chunk
    the header belongs to.
    """

    def __init__(self, header_type, header_size, total_size, data):
        self.type = header_type
        self.header_size = header_size
        self.total_size = total_size
        self.data = data

    @classmethod
    def parse(cls, file):
        """
        Read the header type (2 bytes), header size (2 bytes), and entry size (4 bytes).

        :param file: the xml file e.g. with open('/path/AndroidManifest.xml', 'rb') as file
        :type file: bytesIO
        :return: Returns an instance of itself
        :rtype: ResChunkHeader
        """
        header_data = file.read(8)
        if len(header_data) < 8:
            # End of file
            return None
        header_type, header_size, total_size = struct.unpack('<HHI', header_data)
        return cls(header_type, header_size, total_size, header_data)


class ResStringPoolHeader:
    """
    It reads the string pool header which contains information about the StringPool.
    """

    def __init__(self, header: ResChunkHeader, string_count, style_count, flags, strings_start,
                 styles_start, data):
        self.header = header
        self.string_count = string_count
        self.style_count = style_count
        self.flags = flags
        self.strings_start = strings_start
        self.styles_start = styles_start
        self.data = data

    @classmethod
    def parse(cls, file):
        """
        Read and parse ResStringPoolHeader from the file.

        :param file: the xml file right after the header has been read.
        :type file: bytesIO
        :return: Returns an instance of itself
        :rtype: ResStringPoolHeader
        """
        header = ResChunkHeader.parse(file)
        string_pool_header_data = file.read(20)
        string_count, style_count, flags, strings_start, styles_start = struct.unpack('<IIIII', string_pool_header_data)
        return cls(header, string_count, style_count, flags, strings_start,
                   styles_start, string_pool_header_data)


class StringPoolType:
    """
    The stringPool class which is a composition of the ResStringPoolHeader
    along with the string offsets and the string data.
    """

    def __init__(self, string_pool_header: ResStringPoolHeader, string_offsets, strings, string_pool_data):
        self.str_header = string_pool_header
        self.string_offsets = string_offsets
        self.string_list = strings
        self.data = string_pool_data

    @classmethod
    def read_string_offsets(cls, file, num_of_strings, end_absolute_offset):
        """
        Reads the offset available for each string. Requires to know the number of strings available beforehand.

        :param file: the xml file right after the string pool header has been read.
        :type file: bytesIO
        :param num_of_strings: the calculated number of strings available
        :type num_of_strings: int
        :param end_absolute_offset: the absolute value of the offset where the offsets finish.
        :type end_absolute_offset: int
        :return: Returns a list of strings offsets.
        :rtype: list
        """
        string_offsets = []
        for i in range(0, num_of_strings):
            string_offsets.append(struct.unpack('<I', file.read(4))[0])
        # sanity check as after reading the last string we should be at the end offset as calculated
        if file.tell() != end_absolute_offset:
            logging.warning(
                f"Current file read:{file.tell()} is not as expected to the start of the stringData:{end_absolute_offset})")
        return string_offsets

    @classmethod
    def read_string_offset(cls, file, position):
        try:
            file.seek(position * 4)
            string_offset = struct.unpack('<I', file.read(4))[0]
            return string_offset
        except Exception as e:
            logging.error(f"String offset at position {position} failed to be read: {e}")
            return None

    @classmethod
    def decode_stringpool_mixed_string(cls, file, is_utf8, end_stringpool_offset):
        """
        Handling the different encoding possibilities that can be met.

        :param file: the xml file at the offset where the string is to be read
        :type file: bytesIO
        :param is_utf8: boolean to check if a utf8 string is expected
        :type is_utf8: bool
        :param end_stringpool_offset:
        :type end_stringpool_offset: int
        :return: Returns the decoded string
        :rtype: str
        """
        if not is_utf8:
            # Handle UTF-16 encoded strings
            u16len = struct.unpack('<H', file.read(2))[0]
            if u16len & 0x8000 == 0:
                # Regular UTF-16 string
                content = file.read(u16len * 2).decode('utf-16le')
            else:
                # UTF-16 string with fixup
                u16len_fix = struct.unpack('<H', file.read(2))[0]
                real_length = ((u16len & 0x7FFF) << 16) | u16len_fix
                if real_length > end_stringpool_offset:
                    return ""
                # TODO:a check for non null-terminated strings should be here as well
                content = file.read(real_length * 2).decode('utf-16le')
        else:
            # Handle UTF-8 encoded strings
            u16len = struct.unpack('B', file.read(1))[0]
            file.read(1)
            u8len = u16len
            content = file.read(u8len).decode('utf-8', errors='replace')
            # TODO: fixup is needed here as well, like for the utf16 case

        return content

    @classmethod
    def read_strings(cls, file, string_offsets, strings_start, is_utf8):
        """
        Gets the actual strings based on the offsets retrieved from read_string_offsets().

        :param file: the xml file right after the string pool offsets have been read
        :type file: bytesIO
        :param string_offsets: see -> read_string_offsets()
        :type string_offsets: list
        :param strings_start: the offset at which the string data starts
        :type strings_start: int
        :param is_utf8: boolean to check if a utf8 string is expected
        :type is_utf8: bool
        :return: Returns a list of the string data
        :rtype: list
        """
        strings = []
        for offset in string_offsets:
            # Calculate the absolute offset within the string data +8 for the file header
            absolute_offset = strings_start + offset + 8  # TODO: update this to get the file header size
            # Move the file pointer to the start of the string
            file.seek(absolute_offset)
            # Read the length of the string (in bytes)
            content = cls.decode_stringpool_mixed_string(file, is_utf8, strings_start + string_offsets[-1])
            strings.append(content)
        return strings

    @classmethod
    def read_string(cls, file, string_offset, strings_start, is_utf8, end_stringpool_offset):
        """
        Read a string from the string pool when the offset of it is known already.

        :param file: the string pool data parsed as bytes
        :type file: io.bytesIO
        :param string_offset: the offset at which the string is located in the string pool
        :type string_offset: int
        :param strings_start: the offset at which the string data starts
        :type strings_start: int
        :param is_utf8: boolean to check if a utf8 string is expected
        :type is_utf8: bool
        :param end_stringpool_offset: the offset at which the string pool ends
        :type end_stringpool_offset: int
        :return: Returns the string or None
        :rtype: str or None
        """
        absolute_offset = strings_start + string_offset - 28
        if file.getbuffer().nbytes < absolute_offset:
            return None
        file.seek(absolute_offset)
        string = cls.decode_stringpool_mixed_string(file, is_utf8, end_stringpool_offset)
        return string

    @classmethod
    def get_string_from_pool(cls, position, string_pool_data, end_stringpool_offset, strings_start, is_utf8):
        """
        Retrieve a single string from the String Pool, given its position. It first gets the correct offset of the
        string and then reads the string.

        :param position: The position of the string to be retrieved
        :type position: int
        :param string_pool_data: the string pool data parsed as bytes
        :type string_pool_data: io.BytesIO
        :param end_stringpool_offset: the offset at which the string pool ends
        :type end_stringpool_offset: int
        :param strings_start: the offset at which the string data starts
        :type strings_start: int
        :param is_utf8: boolean to check if a utf8 string is expected
        :type is_utf8: bool
        :return: Returns the string or None
        :rtype: str or None
        """
        try:
            string_offset = cls.read_string_offset(string_pool_data, position)
            if string_offset is None:
                return None
            return cls.read_string(string_pool_data, string_offset, strings_start, is_utf8, end_stringpool_offset)
        except Exception as e:
            logging.exception(f"Exception while retrieving string from pool: {e}")
            return None

    @classmethod
    def parse_lite(cls, file):
        """
        A 'lite' parser that gets the header and then reads the rest of the chunk as a blob of bytes.

        :param file: the AndroidManifest.xml file
        :type file: bytesIO
        :return: returns the header and the chunk data
        :rtype: tuple(ResStringPoolHeader, bytes)
        """
        ResStringPool_header = ResStringPoolHeader.parse(file)
        string_pool_data = read_remaining(file, ResStringPool_header.header)
        while True:  # read any null bytes remaining
            cur_pos = file.tell()
            if file.read(2) == b'\x80\x01':
                file.seek(cur_pos)
                break
            file.seek(cur_pos)
            file.read(1)
        return ResStringPool_header, string_pool_data

    @classmethod
    def parse(cls, file):
        """
        Parse the string pool to acquire the strings used within the axml.

        :param file: the xml file right after the file header is read
        :type file: bytesIO
        :return: Returns an instance of itself
        :rtype: StringPoolType
        """
        string_pool_header = ResStringPoolHeader.parse(file)
        string_pool_start = file.tell()
        size_of_strings_offsets = string_pool_header.strings_start - 28
        # it should be divisible by 4, as 4 bytes are per offset, so we can get accurately the # of strings
        num_of_strings = size_of_strings_offsets // 4
        if not (size_of_strings_offsets / 4).is_integer():
            logging.warning(f"The number of strings in the string pool is not a integer number.")
        string_offsets = cls.read_string_offsets(file, num_of_strings, string_pool_header.strings_start + 8)
        is_utf8 = bool(string_pool_header.flags & (1 << 8))
        string_list = cls.read_strings(file, string_offsets, string_pool_header.strings_start, is_utf8)
        while True:  # read any null bytes remaining
            cur_pos = file.tell()
            if file.read(2) == b'\x80\x01':
                file.seek(cur_pos)
                break
            file.seek(cur_pos)
            file.read(1)
            if file.getbuffer().nbytes < file.tell() + 8:
                raise ValueError("Resource Map header was not detected.")
        string_pool_end = file.tell()
        file.seek(string_pool_start)
        string_pool_data = file.read(string_pool_end - string_pool_start)
        return cls(
            string_pool_header,
            string_offsets,
            string_list,
            string_pool_data
        )


class XmlResourceMapType:
    """
    Resource map class, with the header and the resource IDs.
    """

    def __init__(self, header, resids, resids_data):
        self.header = header
        self.resids = resids
        self.data = resids_data

    @classmethod
    def parse_lite(cls, file):
        """
        A 'lite' parser that gets the header and then reads the rest of the chunk as a blob of bytes.

        :param file: the AndroidManifest.xml file
        :type file: bytesIO
        :return: returns the header and the chunk data
        :rtype: tuple(ResChunkHeader, bytes)
        """
        resource_map_header = ResChunkHeader.parse(file)
        resource_map_data = read_remaining(file, resource_map_header)
        return resource_map_header, resource_map_data

    @classmethod
    def parse(cls, file):
        """
        Parse the resource map and get the resource IDs.

        :param file: the xml file right after the string pool is read
        :type file: bytesIO
        :return: Returns an instance of itself
        :rtype: XmlResourceMapType
        """
        header = ResChunkHeader.parse(file)
        num_resids = (header.total_size - header.header_size) // 4
        resids_data = file.read(num_resids * 4)
        chunks = [resids_data[i:i + 4] for i in range(0, len(resids_data), 4)]
        resids = [struct.unpack('<I', chunk)[0] for chunk in chunks]

        return cls(header, resids, resids_data)


class ResXMLHeader:
    """
    Chunk header used as a header for the elements.
    This header represents the header for the rest of the elements besides the initial header, the string pool and
    the resource map.
    """

    def __init__(self, header: ResChunkHeader, data):
        self.header = header
        # self.xml_header_line_number = header_line_number  # not useful
        # self.xml_header_comment = header_comment          # not useful
        self.data = data

    @classmethod
    def parse(cls, file):
        """
        Supporting header for the elements besides the initial header, the string pool and
        the resource map.

        :param file: the xml file e.g. with open('/path/AndroidManifest.xml', 'rb') as file
        :type file: bytesIO
        :return: Returns an instance of itself
        :rtype: ResXMLHeader
        """
        header = ResChunkHeader.parse(file)
        header_data = b''
        if header.header_size > 8:
            header_data = file.read(header.header_size - 8)
        return cls(header, header_data)


class XmlStartNamespace:
    """
    The actual start of the xml, after this the elements of the xml will be found.
    """

    def __init__(self, header: ResXMLHeader, ext, ext_data):
        self.header = header
        self.ext = ext  # [prefix_index, uri_index]
        self.data = ext_data

    @classmethod
    def parse(cls, file, header_t: ResXMLHeader):
        """
        Parse the starting element of a Namespace
        :param file: the axml already pointing at the right offset
        :type file: bytesIO
        :param header_t: the already read header of the chunk
        :type header_t: ResXMLHeader
        :return: an instance of itself
        :rtype: XmlStartNamespace
        """
        num_exts = (header_t.header.total_size - header_t.header.header_size) // 4
        ext_data = file.read(num_exts * 4)
        chunks = [ext_data[i:i + 4] for i in range(0, len(ext_data), 4)]
        ext = [struct.unpack('<I', chunk)[0] for chunk in chunks]
        return cls(header_t, ext, ext_data)


class XmlEndNamespace:
    """
    Class to represent the end of a Namespace.
    """

    def __init__(self, header: ResXMLHeader, prefix_namespace_index, uri_index, end_namespace_data):
        self.header = header
        self.prefix_namespace_index = prefix_namespace_index
        self.uri_index = uri_index
        self.data = end_namespace_data

    @classmethod
    def parse(cls, file, header_t: ResXMLHeader):
        """
        Parse the ending element of a Namespace.

        :param file: the axml already pointing at the right offset
        :type file: bytesIO
        :param header_t: the already read header of the chunk
        :type header_t: ResXMLHeader
        :return: an instance of itself
        :rtype: XmlEndNamespace
        """
        end_namespace_data = file.read(8)
        prefix_namespace_index, uri_index = struct.unpack('<II', end_namespace_data)
        return cls(header_t, prefix_namespace_index, uri_index, end_namespace_data)


class XmlAttributeElement:
    """
    The attributes within each element within the axml, should be described by this class.
    """

    def __init__(self, full_namespace_index, name_index, raw_value_index, typed_value_size, typed_value_res0,
                 typed_value_datatype, typed_value_data):
        self.full_namespace_index = full_namespace_index
        self.name_index = name_index
        self.raw_value_index = raw_value_index
        self.typed_value_size = typed_value_size
        self.typed_value_res0 = typed_value_res0
        self.typed_value_datatype = typed_value_datatype
        self.typed_value_data = typed_value_data

    @classmethod
    def parse(cls, file, attr_count, attr_size):
        """
        The method is responsible to parse and retrieve the attributes of an element based on the attribute count.
        There are many datatypes that are not read according to the specification (at least for now), but that does
        not affect the main goal of the tool, therefore it is not a priority. For the presentation of the values
        another check is occurring in the process_attributes method.

        :param file: the axml already pointing at the right offset
        :type file: BytesIO
        :param attr_count: The attribute count value part of XmlStartElement.attrext
        :type attr_count: int
        :param attr_size: The attribute size value part of XmlStartElement
        :type attr_size: int
        :return: List of attributes
        :rtype: list
        """
        attrs = []
        for _ in range(0, attr_count):
            tn = file.tell()
            full_namespace_index = struct.unpack('<I', file.read(4))[0]
            name_index = struct.unpack('<I', file.read(4))[0]
            raw_value_index = struct.unpack('<I', file.read(4))[0]
            typed_value_size = struct.unpack('<H', file.read(2))[0]
            typed_value_res0 = struct.unpack('<B', file.read(1))[0]
            typed_value_datatype = struct.unpack('<B', file.read(1))[0]
            if typed_value_datatype == 4:
                typed_value_data = round(struct.unpack('<f', file.read(4))[0], 1)
            elif typed_value_datatype == 5:
                typed_value_data = struct.unpack('<I', file.read(4))[0]
            elif typed_value_datatype == 16:
                typed_value_data = struct.unpack('<i', file.read(4))[0]
            else:
                typed_value_data = struct.unpack('<I', file.read(4))[0]
            attrs.append(cls(full_namespace_index, name_index, raw_value_index, typed_value_size, typed_value_res0,
                             typed_value_datatype, typed_value_data))
            if file.tell() - tn != attr_size:  # check for any dummy data in between attributes
                file.read(attr_size - (file.tell() - tn))
        return attrs


class XmlStartElement:
    """
    The starting point of an element, its attributes are described by XmlAttributeElement.
    The attrext contains information about the element including the attribute count.
    """

    def __init__(self, header: ResXMLHeader, attrext, attributes, start_element_data):
        self.header = header
        self.attrext = attrext
        self.attributes = attributes
        self.data = start_element_data

    @classmethod
    def parse(cls, file, header_t: ResXMLHeader):
        """
        Parse the current element

        :param file: the axml already pointing at the right offset
        :type file: BytesIO
        :param header_t: the already read header of the chunk
        :type header_t: ResXMLHeader
        :return: an instance of itself
        :rtype: XmlStartElement
        """
        attrext_data = file.read(20)
        full_namespace_index, name_index, attr_start, attr_size, attr_count, id_index, class_index, style_index = struct.unpack(
            '<IIHHHHHH', attrext_data)
        attrext = [full_namespace_index, name_index, attr_start, attr_size, attr_count, id_index, class_index,
                   style_index]
        if attr_start != 20:
            # Cover for dummy data between ResXMLTree_attrExt and the 1st ResXMLTree_attribute
            gap_size = attr_start - 20
            file.read(gap_size)
        attributes_data = file.read(attr_size * attr_count)
        attributes = XmlAttributeElement.parse(io.BytesIO(attributes_data), attr_count, attr_size)
        return cls(header_t, attrext, attributes, (attrext_data + attributes_data))


class XmlEndElement:
    """
    The end of an element, where the attrext contains the necessary information on which element it ends.
    """

    def __init__(self, header: ResXMLHeader, attrext, attrext_data):
        self.header = header
        self.attrext = attrext
        self.data = attrext_data

    @classmethod
    def parse(cls, file, header_t: ResXMLHeader):
        """
        Parse the end of an element.

        :param file: the axml already pointing at the right offset
        :type file: bytesIO
        :param header_t: the already read header of the chunk
        :type header_t: ResXMLHeader
        :return: an instance of itself
        :rtype: XmlEndElement
        """
        attrext_data = file.read(8)
        full_namespace_index, name_index = struct.unpack('<II', attrext_data)
        attrext = [full_namespace_index, name_index]
        return cls(header_t, attrext, attrext_data)


class XmlcDataElement:
    """
    A class to cover any CDATA section
    https://developer.android.com/reference/org/w3c/dom/CDATASection
    """

    def __init__(self, header: ResXMLHeader, data_index, typed_value_size, typed_value_res0,
                 typed_value_datatype, typed_value_data, cdata_data):
        self.header = header
        self.data_index = data_index
        self.typed_value_size = typed_value_size
        self.typed_value_res0 = typed_value_res0
        self.typed_value_datatype = typed_value_datatype
        self.typed_value_data = typed_value_data
        self.data = cdata_data

    @classmethod
    def parse(cls, file, header_t: ResXMLHeader):
        """
        Parse the CDATA element.

        :param file: the axml already pointing at the right offset
        :type file: bytesIO
        :param header_t: the already read header of the chunk
        :type header_t: ResXMLHeader
        :return: an instance of itself
        :rtype: XmlcDataElement
        """
        cdata_data = file.read(12)
        data_index, typed_value_size, typed_value_res0, typed_value_datatype, typed_value_data = struct.unpack('<IHBBI', cdata_data)
        return cls(header_t, data_index, typed_value_size, typed_value_res0,
                   typed_value_datatype, typed_value_data, cdata_data)


class ManifestStruct:
    """
    A class to represent the AndroidManifest as a composition
    """

    def __init__(self, header: ResChunkHeader, string_pool: StringPoolType, resource_map: XmlResourceMapType, elements):
        self.header = header
        self.string_pool = string_pool
        self.resource_map = resource_map
        self.elements = elements

    @staticmethod
    def check_reached_element(file: io.BytesIO):
        """
        Static method to check if the next element right after the resource map chunk has been reached.
        Android tolerates unknown chunk types, so we only need to verify
        there's enough data for a header and that the header size is plausible.
        Reference: AOSP ResXMLTree::setTo()

        :param file: The AndroidManifest file
        :type file: io.BytesIO
        """
        min_size = 8  # 2 bytes type, 2 bytes header_size, 4 bytes total_size
        while True:
            cur_pos = file.tell()
            if file.getbuffer().nbytes < cur_pos + min_size:
                break  # not enough data for a header
            try:
                _type, _header_size, _size = struct.unpack('<HHL', file.read(8))
                file.seek(cur_pos)
                if min_size <= _header_size <= _size:
                    return True  # Valid header, regardless of type
            except struct.error:
                break
            file.seek(cur_pos + 1)  # Try next byte if not valid

    @staticmethod
    def parse_next_header(file):
        """
        Dispatcher method to parse the next available header. It takes into account to move on past the header if it
        contains extra info besides the standard ones.
        The dispatcher automatically picks the correct processing method for each chunk type.

        :param file: the axml that will be processed
        :type file: bytesIO
        :raises NotImplementedError: The chunk type identified is not supported
        :return: Dispatches to the appropriate processing method for each chunk type.
        """
        chunk_header_total = ResXMLHeader.parse(file)
        chunk_header = chunk_header_total.header
        if chunk_header is None:  # end of file
            return None
        chunk_type = hex(chunk_header.type)
        handler = chunk_type_handlers.get(chunk_type, chunk_type_handlers['default'])
        return handler(file, chunk_header_total)

    @staticmethod
    def process_elements(file, num_of_elements=None):
        """
        It starts processing the remaining chunks **after** the resource map chunk.

        :param file: the axml that will be processed
        :type file: BytesIO
        :param num_of_elements: how many elements should it process
        :type num_of_elements: int
        :return: Returns all the elements found as their corresponding classes and whether dummy data were found in between.
        :rtype: set(list, set(bool, bool))
        """
        elements = []
        while True:
            cur_pos = file.tell()
            if file.getbuffer().nbytes < cur_pos + 8:
                # we reached the end of the file
                break
            ManifestStruct.check_reached_element(file)
            resXMLTree_node = ResXMLHeader.parse(file)
            cur_elem_data = read_remaining(file, resXMLTree_node.header)
            elem_data = resXMLTree_node.header.data + resXMLTree_node.data + cur_elem_data
            element = ManifestStruct.parse_next_header(io.BytesIO(elem_data))
            if isinstance(element, dict) and "raw" in element:
                logging.warning(f"Unknown chunk type found: {element['type']}")
                continue  # TODO: consider value in collecting this!
            elements.append(element)
            if num_of_elements is None:
                continue
            if len(elements) == num_of_elements:
                break
        return elements

    def get_manifest(self):
        """
        Method to return the AndroidManifest created from this instance

        :return: The AndroidManifest.xml as a string
        :rtype: str
        """
        manifest = create_manifest(self.elements, self.string_pool.string_list)
        return manifest

    @staticmethod
    def parse_lite(manifest, num_of_elements=None):
        """
        Parse the AndroidManifest with a limit on the elements to be parsed after the string pool. The goal of this method
        is to make it possible to partially parse the AndroidManifest and allow faster parsing when needed. Only the
        header is parsed from each chunk, and the rest are there as blobs of bytes.

        :param manifest: The manifest to be processed
        :type manifest: bytesIO
        :param num_of_elements: How many elements of the manifest to process. Usually 3 are enough to get basic info about it.
        :type num_of_elements: int
        :return: A tuple containing four elements: ResChunkHeader, [ResStringPoolHeader, string_pool_data], [ResChunkHeader, resource_map_data], elements
        :rtype: tuple (ResChunkHeader_init, [ResStringPoolHeader, bytes], [ResChunkHeader, bytes], list of bytes)
        """
        ResChunkHeader_init = ResChunkHeader.parse(manifest)
        ResStringPool_header, string_pool_data = StringPoolType.parse_lite(manifest)
        resource_map_header, resource_map_data = XmlResourceMapType.parse_lite(manifest)
        elements = ManifestStruct.process_elements(manifest, num_of_elements=num_of_elements)
        return ResChunkHeader_init, [ResStringPool_header, string_pool_data], [resource_map_header,
                                                                               resource_map_data], elements

    @classmethod
    def parse(cls, file):
        """
        A composition of the rest of the classes available in the apkInspector.axml module, to form the AndroidManifest structure.

        :param file: the axml that will be processed
        :type file: bytesIO
        :return: an instance of itself
        :rtype: ManifestStruct
        """
        header = ResChunkHeader.parse(file)
        string_pool = StringPoolType.parse(file)
        resource_map = XmlResourceMapType.parse(file)
        elements = cls.process_elements(file)
        return cls(header, string_pool, resource_map, elements)


def handle_unknown_chunk(file: io.BytesIO, header_t: ResXMLHeader):
    """
    Default handler for unknown chunk types.
    # ResourceTypes.cpp skips unrecognized chunk types
    # as long as their size and header are valid.
    # Reference: AOSP ResXMLTree::setTo() and ResXMLParser::nextNode()
    """
    data = read_remaining(file, header_t.header)
    # Optional: return raw chunk for logging or malware analysis
    return {
        "type": hex(header_t.header.type),
        "raw": data
    }


chunk_type_handlers = {
    '0x100': XmlStartNamespace.parse,  # RES_XML_START_NAMESPACE_TYPE
    '0x101': XmlEndNamespace.parse,  # RES_XML_END_NAMESPACE_TYPE
    '0x102': XmlStartElement.parse,  # RES_XML_START_ELEMENT_TYPE
    '0x103': XmlEndElement.parse,  # RES_XML_END_ELEMENT_TYPE
    '0x104': XmlcDataElement.parse,  # RES_XML_CDATA_TYPE
    'default': handle_unknown_chunk  # fallback
}

def read_remaining(file: io.BytesIO, header: ResChunkHeader):
    """

    :param file: the current file that is being processed
    :type file: io.BytesIO
    :param header: the header of the current chunk of instance ResChunkHeader
    :type header: ResChunkHeader
    :return: Returns the remaining bytes of the chunk except the header
    :rtype: bytes
    """
    remaining_to_be_read = header.total_size - header.header_size
    return file.read(remaining_to_be_read)


def process_attributes(attributes, string_list, ns_dict):
    """
    Helps in processing the representation of attributes found in each element of the axml. It should be noted that not
    all datatypes are taken into account, meaning that the values of certain attributes might not be represented properly.

    :param attributes: the attributes of an XmlStartElement object as returned by XmlAttributeElement.parse()
    :type attributes: list
    :param string_list: the string data list from the String Pool
    :type string_list: list
    :param ns_dict: a namespace dictionary based on the XmlStartNamespace elements found
    :type ns_dict: dict
    :return: returns a string of all the attributes with their values
    :rtype: str
    """
    attribute_list = []
    for attr in attributes:
        try:
            name = string_list[attr.name_index]
        except:
            continue
        if not name:  # It happens that the attr.name_index points to an empty string in StringPool and you have to use
            # the public.xml. It falls outside the scope of the tool, so I am not going to solve it for now.
            name = f'Unknown_Attribute_Name_{random.randint(1000, 9999)}'
        if "\n" in name:
            # may be obfuscated attribute - https://github.com/REAndroid/APKEditor
            continue
        if attr.typed_value_datatype == 1:  # reference type
            value = f"@{attr.typed_value_data}"
        elif attr.typed_value_datatype == 3:  # string type
            try:
                value = escape_xml_entities(string_list[attr.typed_value_data])
            except:
                value = attr.typed_value_data
        elif attr.typed_value_datatype == 17:  # int-hex type
            value = "0x{:08X}".format(attr.typed_value_data)
        elif attr.typed_value_datatype == 18:  # boolean type
            value = "true" if bool(attr.typed_value_data) else "false"
        elif attr.typed_value_datatype == 0:  # null, used for CData
            return name
        else:
            # TODO: Not accurate enough, values should be represented based on which datatype. Good enough for now
            value = str(attr.typed_value_data)
        if attr.full_namespace_index < len(string_list):
            namespace = string_list[attr.full_namespace_index]
            if not namespace:  # Same as with the empty name, points to an empty string in StringPool.
                namespace = 'android'
            try:
                attribute_list.append(f'{ns_dict[namespace]}:{name}="{value}"')
            except:
                attribute_list.append(f'{namespace.split("/")[-1]}:{name}="{value}"')
        else:
            attribute_list.append(f'{name}="{value}"')

    return ' '.join(attribute_list)


def create_manifest(elements, string_list):
    """
    Method to create the readable XML AndroidManifest.xml file based on the elements discovered from the processed APK

    :param elements: The parsed elements as returned by process_elements()[0]
    :type elements: list
    :param string_list: The string pool data
    :type string_list: list
    :return: The AndroidManifest.xml as a string
    :rtype: str
    """
    android_manifest_xml = []
    namespaces = {}
    ns_dict = {}
    ns_declared = []
    for element in elements:
        if isinstance(element, XmlStartNamespace):
            if element.ext[0] < len(string_list) or element.ext[1] < len(string_list):
                namespaces[string_list[element.ext[0]]] = f'xmlns:{string_list[element.ext[0]]}="{string_list[element.ext[1]]}"'
                ns_dict[string_list[element.ext[1]]] = string_list[element.ext[0]]
        elif isinstance(element, XmlStartElement):
            attributes = process_attributes(element.attributes, string_list, ns_dict)
            attr_ns_list = set(ns.split(':')[0] for ns in attributes.split(' ') if ':' in ns)
            tmp_ns = []  # TODO: Somewhat hacky way to add namespaces/ Maybe improve in future depending on needs
            for vl in attr_ns_list:
                if vl not in ns_declared:
                    if vl in namespaces:
                        tmp_ns.append(namespaces[vl])
                    elif vl == 'android':
                        tmp_ns.append(f'xmlns:android="http://schemas.android.com/apk/res/android"')
                    ns_declared.append(vl)
            if tmp_ns:
                tag_line = f"<{string_list[element.attrext[1]]} {' '.join(tmp_ns)} {attributes}>\n" if attributes else f"<{string_list[element.attrext[1]]}>\n"
            else:
                tag_line = f"<{string_list[element.attrext[1]]} {attributes}>\n" if attributes else f"<{string_list[element.attrext[1]]}>\n"
            android_manifest_xml.append(tag_line)
        elif isinstance(element, XmlcDataElement):
            if android_manifest_xml[-1][-1] == '\n':
                android_manifest_xml[-1] = android_manifest_xml[-1].replace('\n',
                                                                            string_list[element.data_index])
        elif isinstance(element, XmlEndElement):
            name = string_list[element.attrext[1]]
            closing_tag = f"</{name}>" if name == "manifest" else f"</{name}>\n"
            android_manifest_xml.append(closing_tag)
    return ''.join(android_manifest_xml)


def get_manifest(raw_manifest):
    """
    Helper method to directly return the AndroidManifest file as created by create_manifest()

    :param raw_manifest: expects the encoded AndroidManifest.xml file as a file-like object
    :type raw_manifest: bytesIO
    :return: returns the decoded AndroidManifest file
    :rtype: str
    """
    manifest_object = ManifestStruct.parse(raw_manifest)
    return manifest_object.get_manifest()


def parse_apk_for_manifest(inc_apk, raw: bool = False, lite: bool = False, num_of_elements: int = 3):
    """
    Helper method to retrieve the AndroidManifest directly from an APK, either by providing the APK itself or the path.

    :param inc_apk: The path of the APK file or the APK itself
    :type inc_apk: str
    :param raw: Boolean parameter to define whether the manifest is provided as string or bytes
    :type raw: bool
    :param lite: Boolean parameter to define whether the lite parsing would occur or not
    :type lite: bool
    :param num_of_elements: Number of elements to parse from the APK
    :type num_of_elements: int
    :return: Returns the AndroidManifest.xml as string
    :rtype: str
    """
    if raw:
        apk_file = inc_apk
    else:
        with open(inc_apk, 'rb') as apk:
            apk_file = io.BytesIO(apk.read())

    entry_manifest = ZipEntry.parse_single(apk_file, "AndroidManifest.xml")
    manifest_local = entry_manifest.local_headers["AndroidManifest.xml"].to_dict()
    manifest_bytes = extract_file_based_on_header_info(apk_file, manifest_local,
                                                       entry_manifest.central_directory.entries[
                                                           "AndroidManifest.xml"].to_dict())[0]
    if lite:
        manifest = get_manifest_lite(io.BytesIO(manifest_bytes), num_of_elements=num_of_elements)
    else:
        manifest = get_manifest(io.BytesIO(manifest_bytes))
    return manifest


def get_manifest_lite(manifest: io.BytesIO, num_of_elements: int):
    """
    A method to provide 'lite' parsing of the AndroidManifest in order to retrieve a few details as fast as possible.
    Based on the integer 'num_of_elements' being passed as a parameter, it will attempt to fetch this many chunks right
    after the 'resource map' chunk and will get the attributes values of these elements if they are of instance XmlStartElement

    :param manifest: The manifest to be processed
    :type manifest: io.BytesIO
    :param num_of_elements:
    :type num_of_elements: int
    :return: Returns a dictionary of the attributes discovered
    :rtype: dict
    """
    (ResChunkHeader_init,
     [string_pool_ResChunkHeader, string_pool_data],
     [resource_map_header, resource_map_data], elements) = ManifestStruct.parse_lite(manifest,
                                                                                     num_of_elements=num_of_elements)
    end_stringpool_offset = string_pool_ResChunkHeader.header.total_size + 8
    strings_start = string_pool_ResChunkHeader.strings_start
    is_utf8 = bool(string_pool_ResChunkHeader.flags & (1 << 8))
    attributes_dict = {}
    for element in elements:
        if isinstance(element, XmlStartElement):
            for attr in element.attributes:
                if isinstance(attr, XmlAttributeElement):
                    attr_name = StringPoolType.get_string_from_pool(attr.name_index, io.BytesIO(string_pool_data),
                                                                    end_stringpool_offset, strings_start, is_utf8)
                    attribute_value = get_attribute_value(attr_name, attr, end_stringpool_offset, strings_start,
                                                          is_utf8, io.BytesIO(string_pool_data))
                    attributes_dict[attr_name] = attribute_value
    return attributes_dict


def get_attribute_value(attr_name, attribute, end_stringpool_offset, strings_start, is_utf8, string_pool_data):
    """
    Gets the value for a single attribute

    :param attr_name: The attribute name as it has been retrieved by the string pool
    :type attr_name: str
    :param attribute: the parsed attribute itself
    :type attribute: XmlAttributeElement
    :param end_stringpool_offset: The end of string pool offset
    :type end_stringpool_offset: int
    :param strings_start: the strings start offset for the string pool
    :type strings_start: int
    :param is_utf8: boolean to check if a utf8 string is expected
    :type is_utf8: bool
    :param string_pool_data: The string pool data as io.BytesIO
    :type string_pool_data: io.BytesIO
    :return: returns the attribute value
    :rtype: str
    """
    try:
        if attribute.typed_value_datatype == 1:  # reference type
            return f"@{attribute.typed_value_data}"
        elif attribute.typed_value_datatype == 3:  # string type
            str_pool_loc = StringPoolType.get_string_from_pool(attribute.typed_value_data, string_pool_data,
                                                               end_stringpool_offset,
                                                               strings_start, is_utf8)
            return escape_xml_entities(str_pool_loc) if str_pool_loc else str(attribute.typed_value_data)
        elif attribute.typed_value_datatype == 4:  # float type
            str_pool_loc = StringPoolType.get_string_from_pool(attribute.typed_value_data, string_pool_data,
                                                               end_stringpool_offset,
                                                               strings_start, is_utf8)
            if not str_pool_loc:
                str_pool_loc = StringPoolType.get_string_from_pool(attribute.raw_value_index, string_pool_data,
                                                                   end_stringpool_offset,
                                                                   strings_start, is_utf8)
            return str_pool_loc if str_pool_loc else str(attribute.typed_value_data)
        elif attribute.typed_value_datatype == 17:  # int-hex type
            return f"0x{attribute.typed_value_data:08X}"
        elif attribute.typed_value_datatype == 18:  # boolean type
            return "true" if attribute.typed_value_data else "false"
        else:
            return str(attribute.typed_value_data)
    except Exception as e:
        logging.exception(f"Exception processing attribute {attr_name}: {e}")
        return str(attribute.typed_value_data)
