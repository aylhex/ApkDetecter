# -*- coding: utf-8 -*-
import re
import logging
import zipfile
import string

try:
    from androguard.core.dex import DEX
except ImportError:
    DEX = None

class DeepScanner:
    def __init__(self, apk_obj=None, ipa_path=None, binary_path_in_zip=None):
        self.apk = apk_obj
        self.ipa_path = ipa_path
        self.binary_path_in_zip = binary_path_in_zip
        self.is_ipa = (ipa_path is not None)
        
        self.results = {
            "urls": [],
            "ips": [],
            "sensitive_strings": [],
            "anti_debug": [],
            "crypto": []
        }
        
        # Regex Patterns
        self.patterns = {
            "url": re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'),
            "ip": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "ak_sk": re.compile(r'(?i)(access_key|secret_key|api_key|app_secret|app_id).*?["\']([a-zA-Z0-9]{16,})["\']'),
        }

        # Keywords for string search
        self.suspicious_keywords = [
            "root", "su", "superuser", "magisk", "xposed", "frida", 
            "substrate", "hook", "proxy", "vpn", "emulator", "jailbreak", "cydia"
        ]
        
        # Android Patterns
        self.android_anti_debug = [
            "android/os/Debug;->isDebuggerConnected",
            "android/os/Debug;->waitForDebugger",
            "java/lang/System;->exit",
            "ptrace"
        ]
        
        self.android_crypto = [
            "javax/crypto/Cipher",
            "javax/crypto/spec/SecretKeySpec",
            "java/security/MessageDigest"
        ]

        # iOS Patterns
        self.ios_anti_debug = [
            "ptrace",
            "sysctl",
            "getppid", 
            "isatty",
            "ioctl",
            "svc 0x80", # SVC call
            "task_for_pid"
        ]

        self.ios_crypto = [
            "CCCrypt", 
            "CCSha256", 
            "CCSha1",
            "CCMd5",
            "SecItemAdd",
            "SecItemCopyMatching", 
            "SecKeyEncrypt",
            "SecKeyDecrypt"
        ]

    def scan(self, progress_callback=None):
        if self.is_ipa:
            return self._scan_ipa(progress_callback)
        else:
            return self._scan_apk(progress_callback)

    def _scan_apk(self, progress_callback):
        if not self.apk:
            return self.results
            
        dex_files = []
        try:
            # Get all DEX files
            for f in self.apk.get_files():
                if f.endswith('.dex'):
                    dex_files.append(f)
        except:
            pass

        total_dex = len(dex_files)
        if total_dex == 0:
            return self.results

        for idx, dex_path in enumerate(dex_files):
            if progress_callback:
                progress_callback(int((idx / total_dex) * 100), f"Scanning {dex_path}...")

            try:
                dex_data = self.apk.get_file(dex_path)
                if DEX:
                    d = DEX(dex_data)
                    # 1. String Analysis
                    for s in d.get_strings():
                         self._analyze_string(s)
                            
                    # 2. Method/API Analysis
                    all_strings = set(d.get_strings())
                    self._analyze_apis(all_strings)
                else:
                    # Fallback if androguard dex not available
                    strings = self._extract_strings(dex_data)
                    for s in strings:
                        self._analyze_string(s)

            except Exception as e:
                logging.error(f"Error scanning {dex_path}: {e}")

        self._deduplicate()
        return self.results

    def _scan_ipa(self, progress_callback):
        if not self.ipa_path:
            return self.results

        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as z:
                # Use passed binary path if available
                # However, the binary_path might be in a different encoding than what zipfile expects
                # if the zip file has encoding issues (CP437 vs UTF-8).
                # We need to robustly find the file in the zip.
                
                target_binary_info = None
                
                # Helper to normalize names for comparison
                def normalize(name):
                    return name.replace('\\', '/').rstrip('/')

                # 1. Try to find the passed binary path directly
                if self.binary_path_in_zip:
                    try:
                        target_binary_info = z.getinfo(self.binary_path_in_zip)
                    except KeyError:
                        # Failed direct lookup, might be encoding issue or slight path mismatch
                        pass
                
                # 2. If not found, try to search for it using robust encoding check
                if not target_binary_info:
                    logging.info(f"Direct lookup for {self.binary_path_in_zip} failed. Scanning all files in zip...")
                    
                    # Candidate files list for debugging/fallback
                    candidates = []
                    
                    # We look for Payload/*.app/BinaryName
                    for info in z.infolist():
                        # Fix encoding for the name in the zip
                        try:
                            real_name = info.filename.encode('cp437').decode('utf-8')
                        except:
                            try:
                                real_name = info.filename.encode('cp437').decode('gbk')
                            except:
                                real_name = info.filename
                        
                        # Store normalized name for logic
                        norm_real = normalize(real_name)
                        
                        # Debug log for potentially matching files
                        if '.app/' in norm_real and not norm_real.endswith('/'):
                             candidates.append((norm_real, info))

                        # Check if this looks like our binary
                        if self.binary_path_in_zip:
                            # Compare normalized paths
                            # Also try simple filename match if full path fails (sometimes parent dirs differ slightly)
                            target_norm = normalize(self.binary_path_in_zip)
                            target_basename = target_norm.split('/')[-1]
                            real_basename = norm_real.split('/')[-1]

                            if norm_real == target_norm:
                                target_binary_info = info
                                logging.info(f"Found binary via normalized path match: {real_name}")
                                break
                            elif real_basename == target_basename and '.app/' in norm_real:
                                # Strong candidate if basename matches and it's inside an app bundle
                                # But we should be careful not to pick a resource file with same name (unlikely for binary)
                                # Let's store it as a fallback if exact match fails
                                if not target_binary_info:
                                     target_binary_info = info
                                     logging.info(f"Found binary via basename match: {real_name}")
                        else:
                            # Fallback guessing logic
                            # Look for file with same name as .app folder
                            parts = norm_real.split('/')
                            for i, part in enumerate(parts):
                                if part.endswith('.app'):
                                    app_name = part.replace('.app', '')
                                    if i + 1 < len(parts) and parts[i+1] == app_name:
                                         target_binary_info = info
                                         break

                    # If still not found, try the largest file in the .app folder
                    if not target_binary_info and candidates:
                        logging.info("Binary not found via name match. Trying largest file in .app bundle...")
                        largest_file = None
                        max_size = 0
                        for name, info in candidates:
                            # Ignore obvious non-binary files
                            if name.lower().endswith(('.png', '.plist', '.nib', '.storyboardc', '.car', '.mobileprovision', '.cer')):
                                continue
                            if info.file_size > max_size:
                                max_size = info.file_size
                                largest_file = info
                        
                        if largest_file:
                            target_binary_info = largest_file
                            logging.info(f"Selected largest file as binary candidate: {largest_file.filename}")

                if target_binary_info:
                    if progress_callback:
                        progress_callback(10, f"Scanning binary {target_binary_info.filename}...")
                    
                    with z.open(target_binary_info) as f:
                        data = f.read()
                        # Extract strings from binary
                        strings_gen = self._extract_strings(data)
                        
                        # Convert generator to list to get length
                        string_list = list(strings_gen)
                        total = len(string_list)
                        
                        for i, s in enumerate(string_list):
                            if i % 5000 == 0 and progress_callback and total > 0:
                                progress_callback(int((i / total) * 90), "Analyzing strings...")
                            self._analyze_string(s)
                        
                        # Simple API check via strings presence
                        self._analyze_apis(set(string_list))
                            
                else:
                    logging.error(f"Binary {self.binary_path_in_zip} not found in zip (Encoding issue?)")

        except Exception as e:
            logging.error(f"Error scanning IPA: {e}")

        self._deduplicate()
        return self.results

    def _extract_strings(self, data, min_length=4):
        """
        Extract printable strings from binary data
        """
        result = ""
        for b in data:
            c = chr(b)
            if c in string.printable:
                result += c
            else:
                if len(result) >= min_length:
                    yield result
                result = ""
        if len(result) >= min_length:
            yield result

    def _analyze_string(self, s):
        # Check URL
        if self.patterns['url'].match(s):
            self.results['urls'].append(s)
        # Check IP
        elif self.patterns['ip'].match(s) and not s.startswith("0."):
            self.results['ips'].append(s)
        
        # Check Keywords
        s_lower = s.lower()
        for kw in self.suspicious_keywords:
            if kw in s_lower:
                # Store only the string content, not the keyword prefix
                # We can append the keyword as metadata if needed, but user requested clean string
                self.results['sensitive_strings'].append(s)
                break # Avoid adding same string multiple times if it matches multiple keywords

    def _analyze_apis(self, all_strings):
        if self.is_ipa:
            target_anti_debug = self.ios_anti_debug
            target_crypto = self.ios_crypto
        else:
            target_anti_debug = self.android_anti_debug
            target_crypto = self.android_crypto

        for api in target_anti_debug:
            # Loose check
            parts = api.split('->')
            term = parts[-1] if len(parts) > 1 else api
            if term in all_strings:
                 self.results['anti_debug'].append(api)
        
        for api in target_crypto:
             parts = api.split('/')
             term = parts[-1]
             if term in all_strings:
                 self.results['crypto'].append(api)

    def _deduplicate(self):
        for k in self.results:
            self.results[k] = list(set(self.results[k]))

