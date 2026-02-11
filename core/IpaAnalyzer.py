
import zipfile
import plistlib
import os
import hashlib
import sys
import struct
from datetime import datetime

# Ensure libs are in path
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
libs_dir = os.path.join(current_dir, 'libs')
if libs_dir not in sys.path:
    sys.path.insert(0, libs_dir)

from asn1crypto import cms

class IpaAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.info = {}
        self.provision = {}
        self.icon_data = None
        self.error = None
        self.progress_callback = None
        self.is_encrypted = False
        self.binary_path = None # Store binary path for deep scan

    def set_progress_callback(self, callback):
        self.progress_callback = callback

    def _update_progress(self, value, message=""):
        if self.progress_callback:
            self.progress_callback(value, message)

    def _find_zip_entry(self, z, folder, name):
        """
        Robustly find a file in the zip, handling encoding mismatches.
        folder: The folder path in the zip (likely mojibake/cp437)
        name: The target filename (could be UTF-8 from Info.plist)
        """
        # 1. Try direct join (Success if name was also derived from zip listing)
        path = os.path.join(folder, name).replace('\\', '/')
        try:
            return z.getinfo(path)
        except KeyError:
            pass

        # 2. Iterative search in the specific folder
        # We know 'folder' exists in the zip (it was found via namelist)
        # We need to find 'name' inside 'folder', but 'name' might need encoding conversion
        
        # Normalize folder to ensure it ends with /
        if not folder.endswith('/'):
            folder += '/'
            
        # List all files in this folder
        candidates = []
        for n in z.namelist():
            if n.startswith(folder):
                # Get the filename part
                fname = n[len(folder):]
                # Skip subdirectories
                if '/' in fname.rstrip('/'): 
                    continue
                if not fname: 
                    continue
                    
                candidates.append(n)
        
        # Try to match 'name' against candidates
        # Convert 'name' (UTF-8) to potential CP437 mojibake representation?
        # Or convert candidates (CP437) to UTF-8/GBK and compare with 'name'?
        
        for candidate in candidates:
            fname = candidate[len(folder):]
            
            # Try 1: Is it a direct match? (Already checked by getinfo, but logic here covers scanning)
            if fname == name:
                return z.getinfo(candidate)
                
            # Try 2: Decode candidate from cp437 -> gbk/utf-8 and compare with name
            try:
                decoded = fname.encode('cp437').decode('gbk')
                if decoded == name:
                    return z.getinfo(candidate)
            except:
                pass
                
            try:
                decoded = fname.encode('cp437').decode('utf-8')
                if decoded == name:
                    return z.getinfo(candidate)
            except:
                pass

        # 3. Last resort: Return the largest file in the folder (heuristics for main binary)
        best_candidate = None
        max_size = 0
        for cand_path in candidates:
             # Skip known non-binary extensions
             lower_name = cand_path.lower()
             if lower_name.endswith(('.png', '.plist', '.nib', '.car', '.mobileprovision', '.xml', '.json', '.wav', '.mp3')):
                 continue
             
             info = z.getinfo(cand_path)
             if info.file_size > max_size:
                 max_size = info.file_size
                 best_candidate = info
                 
        return best_candidate

    def _calculate_md5_chunked(self, path):
        hash_md5 = hashlib.md5()
        file_size = os.path.getsize(path)
        read_size = 0
        chunk_size = 8192  # 8KB chunks
        
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_md5.update(chunk)
                read_size += len(chunk)
                
                # Progress 0-10%
                percent = int((read_size / file_size) * 10)
                self._update_progress(percent, f"Calculating MD5... ({int((read_size/file_size)*100)}%)")
        
        return hash_md5.hexdigest().upper()

    def analyze(self):
        if not os.path.exists(self.file_path):
            self.error = "File not found"
            return False

        try:
            self._update_progress(0, "Calculating MD5...")
            # File Stats
            stat = os.stat(self.file_path)
            self.info['file_size'] = stat.st_size
            
            # Chunked MD5
            self.info['md5'] = self._calculate_md5_chunked(self.file_path)

            self._update_progress(10, "Reading IPA Structure...")
            with zipfile.ZipFile(self.file_path, 'r') as z:
                # Find Payload/*.app
                app_folder = None
                app_binary_name = None
                app_binary_path = None
                
                namelist = z.namelist()
                total_files = len(namelist)
                
                # Progress 10-30% for scanning files
                for i, name in enumerate(namelist):
                    if i % 100 == 0:
                        percent = 10 + int((i / total_files) * 20)
                        self._update_progress(percent, "Scanning IPA structure...")
                        
                    if name.startswith('Payload/') and name.endswith('.app/'):
                        app_folder = name
                        # Usually binary name matches .app folder name
                        # Payload/Name.app/ -> Name
                        app_binary_name = os.path.splitext(os.path.basename(name.rstrip('/')))[0]
                        # Don't break immediately, scan all to ensure correct progress? 
                        # Actually breaking is fine for performance, just jump progress.
                        break
                
                if not app_folder:
                    self.error = "Invalid IPA: No .app folder found"
                    return False
                
                self._update_progress(30, "Found App Bundle: " + app_folder)
                
                if app_binary_name:
                    # app_binary_name is derived from app_folder basename (mojibake)
                    # So this simple join usually works if binary name matches folder name
                    # But we use the robust finder anyway to be safe
                    # app_binary_path = os.path.join(app_folder, app_binary_name).replace('\\', '/')
                    # self.binary_path = app_binary_path
                    entry = self._find_zip_entry(z, app_folder, app_binary_name)
                    if entry:
                        self.binary_path = entry.filename

                self._update_progress(35, "Parsing Info.plist...")
                # Parse Info.plist
                info_plist_path = os.path.join(app_folder, 'Info.plist').replace('\\', '/')
                try:
                    with z.open(info_plist_path) as f:
                        plist_content = f.read()
                        try:
                            plist_data = plistlib.loads(plist_content)
                        except:
                            pass
                        else:
                            self._parse_info_plist(plist_data)
                except KeyError:
                    self.error = "Info.plist not found"

                # If binary name wasn't guessed correctly, try to use CFBundleExecutable from plist
                if self.info.get('raw_plist') and 'CFBundleExecutable' in self.info['raw_plist']:
                    app_binary_name = self.info['raw_plist']['CFBundleExecutable']
                    # app_binary_name here is UTF-8 (e.g. "网校企业版")
                    # app_folder is Mojibake (e.g. "Payload/τ╜æ...")
                    # Direct join will fail. Use robust finder.
                    entry = self._find_zip_entry(z, app_folder, app_binary_name)
                    if entry:
                        self.binary_path = entry.filename

                self._update_progress(50, "Checking Cryptid (Encryption)...")
                # Check Encryption (Mach-O cryptid)
                if self.binary_path:
                    try:
                        # Use self.binary_path which is the correct internal zip path
                        with z.open(self.binary_path) as f:
                            # Read header to determine if fat binary or thin
                            header = f.read(4)
                            f.seek(0)
                            if len(header) == 4:
                                self.is_encrypted = self._check_cryptid(f)
                    except KeyError:
                        print(f"Binary file not found in IPA: {self.binary_path}")
                    except Exception as e:
                        print(f"Error checking cryptid: {e}")

                self._update_progress(70, "Parsing Provisioning Profile...")
                # Parse embedded.mobileprovision
                prov_path = os.path.join(app_folder, 'embedded.mobileprovision').replace('\\', '/')
                try:
                    with z.open(prov_path) as f:
                        prov_bytes = f.read()
                        self._parse_provision(prov_bytes)
                except KeyError:
                    pass

                self._update_progress(90, "Extracting Icon...")
                # Extract Icon logic...
                icon_name = None
                if 'CFBundleIcons' in self.info.get('raw_plist', {}):
                    try:
                        icons = self.info['raw_plist']['CFBundleIcons'].get('CFBundlePrimaryIcon', {}).get('CFBundleIconFiles', [])
                        if icons:
                            icon_name = icons[-1] 
                    except: pass
                
                if not icon_name and 'CFBundleIconFiles' in self.info.get('raw_plist', {}):
                     try:
                        icons = self.info['raw_plist']['CFBundleIconFiles']
                        if icons:
                            icon_name = icons[-1]
                     except: pass

                if icon_name:
                    candidates = [
                        os.path.join(app_folder, icon_name).replace('\\', '/'),
                        os.path.join(app_folder, icon_name + '.png').replace('\\', '/'),
                        os.path.join(app_folder, icon_name + '@2x.png').replace('\\', '/'),
                        os.path.join(app_folder, icon_name + '@3x.png').replace('\\', '/')
                    ]
                    for name in z.namelist():
                        if name.startswith(app_folder) and icon_name in name and name.endswith('.png'):
                            candidates.append(name)

                    for path in candidates:
                        try:
                            with z.open(path) as f:
                                self.icon_data = f.read()
                                break
                        except KeyError:
                            continue
            
            self._update_progress(100, "Done")

        except Exception as e:
            self.error = f"Analysis failed: {str(e)}"
            import traceback
            traceback.print_exc()
            return False
        
        return True

    def _check_cryptid(self, f):
        """
        Check LC_ENCRYPTION_INFO or LC_ENCRYPTION_INFO_64 load commands in Mach-O binary.
        Returns True if cryptid != 0 (Encrypted/AppStore), False otherwise.
        Handles Fat Binaries (Universal) by checking all architectures.
        """
        MH_MAGIC = 0xfeedface
        MH_CIGAM = 0xcefaedfe
        MH_MAGIC_64 = 0xfeedfacf
        MH_CIGAM_64 = 0xcffaedfe
        FAT_MAGIC = 0xcafebabe
        FAT_CIGAM = 0xbebafeca
        
        LC_ENCRYPTION_INFO = 0x21
        LC_ENCRYPTION_INFO_64 = 0x2C

        def read_uint32(fh, endian='>'): 
            d = fh.read(4)
            if len(d) < 4: return None
            return struct.unpack(endian + 'I', d)[0]

        magic_bytes = f.read(4)
        f.seek(0)
        
        if len(magic_bytes) < 4: return False
        
        magic = struct.unpack('>I', magic_bytes)[0]
        
        # Determine architectures to check
        archs = [] # (offset, size)
        
        if magic == FAT_MAGIC or magic == FAT_CIGAM:
            # Fat Binary
            endian = '>' # Fat header is always big-endian
            f.seek(4)
            nfat_arch = read_uint32(f, endian)
            
            for i in range(nfat_arch):
                # fat_arch struct: cpu_type, cpu_subtype, offset, size, align
                f.seek(8 + i * 20) # 4+4 header + 20 bytes per arch
                cpu_type = read_uint32(f, endian)
                cpu_subtype = read_uint32(f, endian)
                offset = read_uint32(f, endian)
                size = read_uint32(f, endian)
                archs.append(offset)
        else:
            # Thin Binary
            archs.append(0)
            
        for offset in archs:
            f.seek(offset)
            magic_bytes = f.read(4)
            if len(magic_bytes) < 4: continue
            
            magic = struct.unpack('>I', magic_bytes)[0]
            
            is_64 = False
            endian = '<' # Default little endian for mach-o (ARM)
            
            if magic == MH_MAGIC: pass
            elif magic == MH_CIGAM: endian = '>'
            elif magic == MH_MAGIC_64: is_64 = True
            elif magic == MH_CIGAM_64: 
                is_64 = True
                endian = '>'
            else:
                continue # Unknown magic
                
            # Read mach_header
            # magic(4) + cputype(4) + cpusubtype(4) + filetype(4) + ncmds(4) + sizeofcmds(4) + flags(4) [+ reserved(4) if 64]
            header_size = 28 if not is_64 else 32
            
            f.seek(offset + 16) # Skip to ncmds
            ncmds = read_uint32(f, endian)
            
            # Start of Load Commands
            f.seek(offset + header_size)
            
            for _ in range(ncmds):
                # load_command struct: cmd(4), cmdsize(4)
                cmd_start = f.tell()
                cmd = read_uint32(f, endian)
                cmd_size = read_uint32(f, endian)
                
                if cmd == LC_ENCRYPTION_INFO or cmd == LC_ENCRYPTION_INFO_64:
                    # encryption_info_command: cmd, cmdsize, cryptoff, cryptsize, cryptid
                    # We need cryptid (offset 16 from start of cmd)
                    f.seek(cmd_start + 16)
                    cryptid = read_uint32(f, endian)
                    if cryptid and cryptid > 0:
                        return True # Found encryption!
                
                f.seek(cmd_start + cmd_size)
                
        return False

    def _parse_info_plist(self, plist):
        self.info['raw_plist'] = plist
        self.info['package_name'] = plist.get('CFBundleIdentifier', 'Unknown')
        self.info['app_name'] = plist.get('CFBundleDisplayName', plist.get('CFBundleName', 'Unknown'))
        self.info['version_name'] = plist.get('CFBundleShortVersionString', '')
        self.info['version_code'] = plist.get('CFBundleVersion', '')
        self.info['min_os'] = plist.get('MinimumOSVersion', '')
        self.info['platform'] = plist.get('DTPlatformName', 'ios')
        self.info['supported_platforms'] = plist.get('CFBundleSupportedPlatforms', [])
        self.info['url_schemes'] = []
        
        if 'CFBundleURLTypes' in plist:
            for url_type in plist['CFBundleURLTypes']:
                schemes = url_type.get('CFBundleURLSchemes', [])
                self.info['url_schemes'].extend(schemes)

    def _parse_provision(self, content):
        try:
            content_info = cms.ContentInfo.load(content)
            signed_data = content_info['content']
            encap_content = signed_data['encap_content_info']
            plist_bytes = encap_content['content'].native
            data = plistlib.loads(plist_bytes)
            
            self.provision = {
                'app_id_name': data.get('AppIDName'),
                'team_name': data.get('TeamName'),
                'team_id': data.get('TeamIdentifier', [''])[0],
                'uuid': data.get('UUID'),
                'creation_date': data.get('CreationDate'),
                'expiration_date': data.get('ExpirationDate'),
                'entitlements': data.get('Entitlements', {}),
                'provisioned_devices': data.get('ProvisionedDevices', [])
            }
        except Exception as e:
            print(f"Error parsing mobileprovision: {e}")

    def get_basic_info(self):
        # Determine protection status text
        # If cryptid == 1, it's Encrypted (AppStore build, not cracked) -> "未脱壳"
        # If cryptid == 0, it's Decrypted (Cracked/Debug build) -> "已脱壳"
        protect_status = "未脱壳 (Encrypted)" if self.is_encrypted else "已脱壳 (Decrypted)"
        
        return {
            'name': self.info.get('app_name'),
            'package': self.info.get('package_name'),
            'version': f"{self.info.get('version_name')} ({self.info.get('version_code')})",
            'min_sdk': f"iOS {self.info.get('min_os')}",
            'target_sdk': 'N/A', 
            'size': self._format_size(self.info.get('file_size', 0)),
            'md5': self.info.get('md5'),
            'protect': protect_status
        }
    
    def get_details(self):
        return {
            'url_schemes': self.info.get('url_schemes', []),
            'platform': self.info.get('platform'),
            'supported_platforms': self.info.get('supported_platforms'),
            'provision': self.provision
        }

    def _format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
