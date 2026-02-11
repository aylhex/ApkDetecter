
from PyQt5 import QtWidgets, QtCore, QtGui
import os
import platform

class AppInfoWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(AppInfoWidget, self).__init__(parent)
        self.init_ui()

    def init_ui(self):
        self.layout = QtWidgets.QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(10)

        # Header Section
        self.header_frame = QtWidgets.QFrame()
        self.header_frame.setObjectName("HeaderFrame")
        self.header_layout = QtWidgets.QHBoxLayout(self.header_frame)
        self.header_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop) # Align Top
        self.header_layout.setSpacing(20)
        
        # Icon
        self.icon_label = QtWidgets.QLabel()
        self.icon_label.setFixedSize(125, 125)
        self.icon_label.setAlignment(QtCore.Qt.AlignCenter)
        self.icon_label.setStyleSheet("background-color: #333; border-radius: 10px;")
        
        # Info Block
        self.title_info_layout = QtWidgets.QVBoxLayout()
        self.title_info_layout.setAlignment(QtCore.Qt.AlignTop) # Also Align Top
        self.title_info_layout.setSpacing(5)
        self.title_info_layout.setContentsMargins(0, 5, 0, 0) 
        
        # Platform specific font sizes
        if platform.system() == 'Windows':
            name_size = "30px"
            pkg_size = "29px"
        else:
            name_size = "18px"
            pkg_size = "14px"

        self.app_name_label = QtWidgets.QLabel("App Name")
        self.app_name_label.setStyleSheet(f"font-size: {name_size}; font-weight: bold; color: #fff;")
        self.package_label = QtWidgets.QLabel("com.example.app")
        self.package_label.setStyleSheet(f"color: #aaa; font-size: {pkg_size};")
        self.version_label = QtWidgets.QLabel("v1.0.0")
        self.version_label.setStyleSheet("color: #4da6ff; font-weight: bold;")
        
        self.title_info_layout.addWidget(self.app_name_label)
        self.title_info_layout.addWidget(self.package_label)
        self.title_info_layout.addWidget(self.version_label)
        
        self.header_layout.addWidget(self.icon_label)
        self.header_layout.addLayout(self.title_info_layout)
        self.header_layout.addStretch()

        self.layout.addWidget(self.header_frame)

        # Tabs
        self.tabs = QtWidgets.QTabWidget()
        self.layout.addWidget(self.tabs)

        # Tab 1: Basic Info
        self.tab_basic = QtWidgets.QWidget()
        self.tabs.addTab(self.tab_basic, "Basic Info")
        self.init_basic_tab()

        # Tab 2: Permissions (Was Advanced Info)
        self.tab_perms = QtWidgets.QWidget()
        self.tabs.addTab(self.tab_perms, "Permissions & Entitlements")
        self.init_perms_tab()
        
        # Tab 3: Components (Dynamic)
        self.tab_components = QtWidgets.QTextEdit()
        self.tab_components.setReadOnly(True)
        self.tabs.addTab(self.tab_components, "Components")

    def init_basic_tab(self):
        # Using a ScrollArea because Cert info can be long
        self.basic_scroll = QtWidgets.QScrollArea(self.tab_basic)
        self.basic_scroll.setWidgetResizable(True)
        self.basic_scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        
        # Main Layout for Tab (holds ScrollArea)
        tab_layout = QtWidgets.QVBoxLayout(self.tab_basic)
        tab_layout.setContentsMargins(0,0,0,0)
        tab_layout.addWidget(self.basic_scroll)
        
        # Content Widget inside ScrollArea
        self.basic_content = QtWidgets.QWidget()
        self.basic_scroll.setWidget(self.basic_content)
        
        layout = QtWidgets.QVBoxLayout(self.basic_content)
        layout.setAlignment(QtCore.Qt.AlignTop)
        layout.setSpacing(15)

        # --- Grid for key-value pairs ---
        self.grid_widget = QtWidgets.QWidget()
        grid_layout = QtWidgets.QGridLayout(self.grid_widget)
        grid_layout.setContentsMargins(0,0,0,0)
        
        self.basic_labels = {}
        keys = [
            ("Size", "size"),
            ("MD5", "md5"),
            ("Min SDK / OS", "min_sdk"),
            ("Target SDK", "target_sdk"),
            ("Protection", "protect")
        ]

        row = 0
        for label_text, key in keys:
            lbl = QtWidgets.QLabel(label_text + ":")
            lbl.setStyleSheet("color: #ccc; font-weight: bold;")
            val = QtWidgets.QLineEdit()
            val.setReadOnly(True)
            val.setObjectName(f"val_{key}")
            
            grid_layout.addWidget(lbl, row, 0)
            grid_layout.addWidget(val, row, 1)
            self.basic_labels[key] = val
            row += 1
            
        layout.addWidget(self.grid_widget)
        
        # --- Certificate / Provisioning Info Section ---
        self.cert_label = QtWidgets.QLabel("Certificate / Signature Info")
        
        if platform.system() == 'Windows':
            cert_size = "26px"
        else:
            cert_size = "16px"
            
        self.cert_label.setStyleSheet(f"font-size: {cert_size}; font-weight: bold; color: #4da6ff; margin-top: 20px; margin-bottom: 5px;")
        layout.addWidget(self.cert_label)
        
        self.cert_text = QtWidgets.QTextEdit()
        self.cert_text.setReadOnly(True)
        # Allow it to expand
        self.cert_text.setMinimumHeight(200)
        layout.addWidget(self.cert_text)


    def init_perms_tab(self):
        layout = QtWidgets.QVBoxLayout(self.tab_perms)
        self.perms_text = QtWidgets.QTextEdit()
        self.perms_text.setReadOnly(True)
        layout.addWidget(self.perms_text)

    def update_data(self, analyzer_type, analyzer):
        # Update Header
        info = analyzer.get_basic_info()
        self.app_name_label.setText(str(info.get('name', 'Unknown')))
        self.package_label.setText(str(info.get('package', 'Unknown')))
        self.version_label.setText(str(info.get('version', 'Unknown')))

        # Update Icon
        if analyzer.icon_data:
            pixmap = QtGui.QPixmap()
            if not pixmap.loadFromData(analyzer.icon_data):
                self.icon_label.setText("Bad Icon")
            else:
                self.icon_label.setPixmap(pixmap.scaled(100, 100, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation))
        else:
            self.icon_label.setText("No Icon")

        # Update Basic Info (Grid)
        for key, widget in self.basic_labels.items():
            val = info.get(key, 'N/A')
            widget.setText(str(val))

        # Update Cert/Prov Info & Permissions based on type
        if analyzer_type == 'apk':
            self._update_apk_details(analyzer)
        else:
            self._update_ipa_details(analyzer)

    def _update_apk_details(self, analyzer):
        # 1. Certificate Info (Now in Basic Tab)
        content = ""
        cert = analyzer.cert_info
        if cert:
            content += f"<b>Issuer:</b> {cert.get('issuer')}<br>"
            content += f"<b>Subject:</b> {cert.get('subject')}<br>"
            content += f"<b>Serial:</b> {cert.get('serial')}<br>"
            content += f"<b>SHA1:</b> {cert.get('sha1')}<br>"
            content += f"<b>SHA256:</b> {cert.get('sha256')}<br>"
        else:
            content += "No certificate info found.<br>"
        
        self.cert_text.setHtml(content)

        # 2. Permissions (Now in Permissions Tab)
        perm_content = "<h2>Permissions</h2>"
        perms = analyzer.info.get('permissions', [])
        if perms:
            perm_content += "<ul>"
            for p in perms:
                perm_content += f"<li>{p}</li>"
            perm_content += "</ul>"
        else:
            perm_content += "<p>No permissions requested.</p>"

        self.perms_text.setHtml(perm_content)

        # 3. Components
        comp_text = "Activities:\n" + "\n".join(analyzer.info.get('activities', []))
        comp_text += "\n\nServices:\n" + "\n".join(analyzer.info.get('services', []))
        comp_text += "\n\nReceivers:\n" + "\n".join(analyzer.info.get('receivers', []))
        comp_text += "\n\nProviders:\n" + "\n".join(analyzer.info.get('providers', []))
        self.tab_components.setText(comp_text)

    def _update_ipa_details(self, analyzer):
        details = analyzer.get_details()
        prov = details.get('provision', {})

        # 1. Provisioning Info (Now in Basic Tab)
        content = ""
        if prov:
            content += f"<b>App ID Name:</b> {prov.get('app_id_name')}<br>"
            content += f"<b>Team Name:</b> {prov.get('team_name')} ({prov.get('team_id')})<br>"
            content += f"<b>UUID:</b> {prov.get('uuid')}<br>"
            content += f"<b>Created:</b> {prov.get('creation_date')}<br>"
            content += f"<b>Expires:</b> {prov.get('expiration_date')}<br>"
            content += "<h3>Provisioned Devices</h3><ul>"
            for dev in prov.get('provisioned_devices', []):
                content += f"<li>{dev}</li>"
            content += "</ul>"
        else:
            content += "<p>No embedded.mobileprovision found.</p>"
            
        self.cert_text.setHtml(content)

        # 2. Entitlements (Now in Permissions Tab)
        perm_content = "<h2>Entitlements</h2>"
        if prov:
            perm_content += "<ul>"
            for k, v in prov.get('entitlements', {}).items():
                perm_content += f"<li><b>{k}:</b> {v}</li>"
            perm_content += "</ul>"
        else:
             perm_content += "<p>No entitlements found.</p>"
        
        self.perms_text.setHtml(perm_content)

        # 3. Components
        comp_text = "URL Schemes:\n"
        for scheme in details.get('url_schemes', []):
            comp_text += f"- {scheme}\n"
        
        comp_text += f"\nSupported Platforms: {details.get('supported_platforms')}"
        comp_text += f"\nDTPlatformName: {details.get('platform')}"
        
        self.tab_components.setText(comp_text)
