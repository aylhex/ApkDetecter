# -*- coding: utf-8 -*-
__author__ = 'Andy'

from androguard.core.dex import DEX

class InitDEX:
    def __init__(self, apk_obj):
        self.apk = apk_obj
        self.dexheader = {}

    def getDexInfo(self):
        self.dexheader = {}
        try:
            # Get the first dex file
            # androguard returns bytes, so we need to wrap it in DEX object
            dex_files = list(self.apk.get_all_dex())
            if not dex_files:
                return {}
            
            d = DEX(dex_files[0])
            
            # Helper to format values
            def fmt(val):
                if val is None:
                    return ""
                if isinstance(val, int):
                    return "%X" % val
                if isinstance(val, bytes):
                    return val.hex().upper()
                return str(val)

            h = d.header
            
            # Use getattr to be safe with different androguard versions, or assume standard fields
            self.dexheader["header_magic"] = fmt(getattr(h, "magic", b""))
            self.dexheader["header_checksum"] = fmt(getattr(h, "checksum", 0))
            self.dexheader["header_signature"] = fmt(getattr(h, "signature", b""))
            self.dexheader["header_fileSize"] = fmt(getattr(h, "file_size", 0))
            self.dexheader["header_headerSize"] = fmt(getattr(h, "header_size", 0))
            self.dexheader["header_endianTag"] = fmt(getattr(h, "endian_tag", 0))
            self.dexheader["header_linkSize"] = fmt(getattr(h, "link_size", 0))
            self.dexheader["header_linkOff"] = fmt(getattr(h, "link_off", 0))
            self.dexheader["header_mapOff"] = fmt(getattr(h, "map_off", 0))
            self.dexheader["header_stringIdsSize"] = fmt(getattr(h, "string_ids_size", 0))
            self.dexheader["header_stringIdsOff"] = fmt(getattr(h, "string_ids_off", 0))
            self.dexheader["header_typeIdsSize"] = fmt(getattr(h, "type_ids_size", 0))
            self.dexheader["header_typeIdsOff"] = fmt(getattr(h, "type_ids_off", 0))
            self.dexheader["header_protoIdsSize"] = fmt(getattr(h, "proto_ids_size", 0))
            self.dexheader["header_protoIdsOff"] = fmt(getattr(h, "proto_ids_off", 0))
            self.dexheader["header_fieldIdsSize"] = fmt(getattr(h, "field_ids_size", 0))
            self.dexheader["header_fieldIdsOff"] = fmt(getattr(h, "field_ids_off", 0))
            self.dexheader["header_methodIdsSize"] = fmt(getattr(h, "method_ids_size", 0))
            self.dexheader["header_methodIdsOff"] = fmt(getattr(h, "method_ids_off", 0))
            self.dexheader["header_classDefsSize"] = fmt(getattr(h, "class_defs_size", 0))
            self.dexheader["header_classDefsOff"] = fmt(getattr(h, "class_defs_off", 0))
            self.dexheader["header_dataSize"] = fmt(getattr(h, "data_size", 0))
            self.dexheader["header_dataOff"] = fmt(getattr(h, "data_off", 0))

        except Exception as e:
            print(f"Error getting DEX info: {e}")
            import traceback
            traceback.print_exc()

        return self.dexheader
