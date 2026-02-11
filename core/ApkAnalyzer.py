
import os
import hashlib
import sys
import zipfile
import re
import logging
from datetime import datetime

# Import existing helpers
try:
    from CheckProtect import CheckProtect
except ImportError:
    current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    from CheckProtect import CheckProtect

from androguard.core.apk import APK

# Try to import loguru to check if it's available in the environment
try:
    from loguru import logger as loguru_logger
    HAS_LOGURU = True
except ImportError:
    HAS_LOGURU = False

class ApkAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.apk = None
        self.info = {}
        self.cert_info = {}
        self.protect_info = ""
        self.icon_data = None
        self.error = None
        self.progress_callback = None
        self.loguru_sink_id = None
        
        # Capture Androguard logs
        self.log_buffer = []
        self._setup_logging()

    def _setup_logging(self):
        # 1. Setup Standard Logging Hook
        class CallbackHandler(logging.Handler):
            def __init__(self, callback):
                super().__init__()
                self.callback = callback
                self.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)s - %(message)s'))

            def emit(self, record):
                msg = self.format(record)
                if self.callback:
                    self.callback(msg)

        self.log_handler = CallbackHandler(self._log_callback)
        
        # Hook into multiple potential loggers
        loggers_to_hook = ['androguard', 'androguard.core.axml', 'androguard.core.apk']
        for name in loggers_to_hook:
            logger = logging.getLogger(name)
            logger.setLevel(logging.DEBUG)
            logger.addHandler(self.log_handler)

        # 2. Setup Loguru Hook (if available)
        # Many newer Androguard versions use loguru exclusively
        if HAS_LOGURU:
            # We add a sink that calls our callback
            # format matches the user's example style
            self.loguru_sink_id = loguru_logger.add(
                self._loguru_callback, 
                level="DEBUG", 
                format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}"
            )

    def _log_callback(self, msg):
        # Heuristic: Increment progress for every log message during parsing phase
        if hasattr(self, '_parsing_progress_min') and hasattr(self, '_parsing_progress_max'):
            self._parsing_log_count += 1
            # Logarithmic-ish scale to prevent hitting max too early
            # Assume ~50 log messages for a typical APK parse
            increment = min(self._parsing_log_count * 0.5, (self._parsing_progress_max - self._parsing_progress_min))
            current = int(self._parsing_progress_min + increment)
            if current > self._parsing_progress_max:
                current = self._parsing_progress_max
            
            if self.progress_callback:
                self.progress_callback(current, msg)
        else:
            if self.progress_callback:
                self.progress_callback(-1, msg)

    def _loguru_callback(self, msg):
        # loguru 'msg' is a string already formatted
        if self.progress_callback:
            # Reuse logic
            self._log_callback(msg.strip())

    def set_progress_callback(self, callback):
        self.progress_callback = callback

    def _update_progress(self, value, message=""):
        if self.progress_callback:
            self.progress_callback(value, message)

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

            self._update_progress(15, "Parsing APK Manifest (This may take a while)...")
            
            # Define a helper to simulate progress during the blocking APK() call via log hooks
            # We map log events to progress range 15% -> 40%
            self._parsing_progress_min = 15
            self._parsing_progress_max = 40
            self._parsing_log_count = 0
            
            # Androguard Analysis (APK only, no DEX)
            self.apk = APK(self.file_path)
            
            # Basic Info
            self.info['package_name'] = self.apk.get_package()
            self.info['app_name'] = self.apk.get_app_name()
            self.info['version_name'] = self.apk.get_androidversion_name()
            self.info['version_code'] = self.apk.get_androidversion_code()
            self.info['min_sdk'] = self.apk.get_min_sdk_version()
            self.info['target_sdk'] = self.apk.get_target_sdk_version()
            
            self._update_progress(45, "Extracting Icon...")
            # Icon Extraction Strategy
            # 1. Try get_app_icon()
            # 2. If it returns None or XML, try to search for high-res PNGs in standard locations
            
            try:
                icon_path = self.apk.get_app_icon()
                logging.getLogger('androguard').info(f"Original icon path: {icon_path}")
                if HAS_LOGURU: loguru_logger.info(f"Original icon path: {icon_path}")
                
                # Check if icon is XML (Adaptive Icon) or None
                is_valid_icon = False
                if icon_path and not icon_path.endswith('.xml'):
                    try:
                        self.icon_data = self.apk.get_file(icon_path)
                        is_valid_icon = True
                    except:
                        pass
                
                if not is_valid_icon:
                    msg = "Attempting fallback icon search..."
                    logging.getLogger('androguard').info(msg)
                    if HAS_LOGURU: loguru_logger.info(msg)
                    
                    # Fallback Strategy: Search for PNG icons
                    files = self.apk.get_files()
                    
                    # Priority list for densities
                    densities = ['xxxhdpi', 'xxhdpi', 'xhdpi', 'hdpi', 'mdpi']
                    
                    # Keywords to look for
                    icon_keywords = ['ic_launcher', 'icon', 'ic_app', 'launcher']
                    if icon_path:
                        # Try to use the basename of the reported icon path (even if xml)
                        # e.g. res/mipmap-anydpi-v26/ic_launcher.xml -> ic_launcher
                        basename = os.path.splitext(os.path.basename(icon_path))[0]
                        icon_keywords.insert(0, basename)
                        # Sometimes xml is ic_launcher_round, but png is ic_launcher
                        if '_round' in basename:
                            icon_keywords.insert(1, basename.replace('_round', ''))
                    
                    best_icon = None
                    
                    # Strategy A: Strict density + keyword match
                    for density in densities:
                        for keyword in icon_keywords:
                            pattern = re.compile(f".*res/.*{density}.*/.*{keyword}.*\.png$", re.IGNORECASE)
                            for f in files:
                                if pattern.match(f):
                                    best_icon = f
                                    break
                            if best_icon: break
                        if best_icon: break
                    
                    # Strategy B: Loose match in res/ (any density, strict keyword)
                    if not best_icon:
                        for keyword in icon_keywords:
                            for f in files:
                                if f.endswith(f"/{keyword}.png"):
                                    best_icon = f
                                    break
                            if best_icon: break

                    # Strategy C: Desperation - ANY png with 'launcher' or 'icon' in name
                    if not best_icon:
                        for f in files:
                            if f.endswith('.png') and ('launcher' in f or 'icon' in f) and 'notification' not in f:
                                best_icon = f
                                break

                    # Strategy D: The "Big Gun" - Find the largest PNGs in the APK (heuristic)
                    if not best_icon:
                        msg = "Strategy D: Searching by file size..."
                        logging.getLogger('androguard').info(msg)
                        if HAS_LOGURU: loguru_logger.info(msg)
                        
                        png_files = []
                        with zipfile.ZipFile(self.file_path, 'r') as z:
                            for info in z.infolist():
                                if info.filename.endswith('.png') and not info.filename.endswith('.9.png'):
                                    if 'assets/' not in info.filename:
                                        png_files.append(info)
                        
                        # Sort by size descending
                        png_files.sort(key=lambda x: x.file_size, reverse=True)
                        
                        if png_files:
                            best_icon = png_files[0].filename
                            msg = f"Strategy D picked largest PNG: {best_icon} ({png_files[0].file_size} bytes)"
                            logging.getLogger('androguard').info(msg)
                            if HAS_LOGURU: loguru_logger.info(msg)

                    if best_icon:
                        msg = f"Fallback icon found: {best_icon}"
                        logging.getLogger('androguard').info(msg)
                        if HAS_LOGURU: loguru_logger.info(msg)
                        self.icon_data = self.apk.get_file(best_icon)
                    else:
                        msg = "No fallback icon found."
                        logging.getLogger('androguard').warning(msg)
                        if HAS_LOGURU: loguru_logger.warning(msg)
                    
            except Exception as e:
                msg = f"Error getting icon: {e}"
                logging.getLogger('androguard').error(msg)
                if HAS_LOGURU: loguru_logger.error(msg)

            self._update_progress(60, "Analyzing Certificate...")
            # Cert Info (Fast Way)
            try:
                certs = self.apk.get_certificates()
                if certs:
                    cert = certs[0]
                    self.cert_info = {
                        'serial': hex(cert.serial_number)[2:].upper(),
                        'issuer': cert.issuer.human_friendly,
                        'subject': cert.subject.human_friendly,
                        'sha1': cert.sha1_fingerprint.replace(" ", ":"),
                        'sha256': cert.sha256_fingerprint.replace(" ", ":")
                    }
            except Exception as e:
                msg = f"Error getting cert info: {e}"
                logging.getLogger('androguard').error(msg)
                if HAS_LOGURU: loguru_logger.error(msg)

            self._update_progress(80, "Checking Protection...")
            # Protection
            try:
                cp = CheckProtect(self.apk)
                self.protect_info = cp.check_protectflag()
            except Exception as e:
                self.protect_info = f"Check failed: {e}"

            # Components
            self.info['activities'] = self.apk.get_activities()
            self.info['services'] = self.apk.get_services()
            self.info['receivers'] = self.apk.get_receivers()
            self.info['providers'] = self.apk.get_providers()
            self.info['permissions'] = self.apk.get_permissions()

            self._update_progress(100, "Done")

        except Exception as e:
            self.error = f"Analysis failed: {str(e)}"
            import traceback
            traceback.print_exc()
            return False
        finally:
             # Clean up standard logger
             loggers_to_hook = ['androguard', 'androguard.core.axml', 'androguard.core.apk']
             for name in loggers_to_hook:
                 if hasattr(self, 'log_handler'):
                     logging.getLogger(name).removeHandler(self.log_handler)
             
             # Clean up loguru
             if HAS_LOGURU and self.loguru_sink_id is not None:
                 try:
                     loguru_logger.remove(self.loguru_sink_id)
                 except: pass
        
        return True

    def get_basic_info(self):
        return {
            'name': self.info.get('app_name'),
            'package': self.info.get('package_name'),
            'version': f"{self.info.get('version_name')} ({self.info.get('version_code')})",
            'min_sdk': self.info.get('min_sdk'),
            'target_sdk': self.info.get('target_sdk'),
            'size': self._format_size(self.info.get('file_size', 0)),
            'md5': self.info.get('md5'),
            'protect': self.protect_info
        }

    def _format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
