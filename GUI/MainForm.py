
from PyQt5 import QtWidgets, QtCore, QtGui
import sys
import os
import platform

from GUI.AppInfoWidget import AppInfoWidget
from Core.ApkAnalyzer import ApkAnalyzer
from Core.IpaAnalyzer import IpaAnalyzer
from Core.DeepScanner import DeepScanner

class DeepScanThread(QtCore.QThread):
    progress_signal = QtCore.pyqtSignal(int, str)
    finished_signal = QtCore.pyqtSignal(object)

    def __init__(self, apk_obj=None, ipa_path=None, analyzer=None):
        super(DeepScanThread, self).__init__()
        self.apk = apk_obj
        self.ipa_path = ipa_path
        self.analyzer = analyzer

    def run(self):
        binary_path_in_zip = None
        if self.analyzer and hasattr(self.analyzer, 'binary_path'):
            binary_path_in_zip = self.analyzer.binary_path
            
        scanner = DeepScanner(self.apk, self.ipa_path, binary_path_in_zip)
        results = scanner.scan(self.emit_progress)
        self.finished_signal.emit(results)

    def emit_progress(self, value, message):
        self.progress_signal.emit(value, message)

class AnalysisThread(QtCore.QThread):
    progress_signal = QtCore.pyqtSignal(int, str)
    finished_signal = QtCore.pyqtSignal(bool, object, str)

    def __init__(self, file_path):
        super(AnalysisThread, self).__init__()
        self.file_path = file_path
        self.analyzer = None
        self.analyzer_type = None

    def run(self):
        try:
            if self.file_path.lower().endswith('.apk'):
                self.analyzer = ApkAnalyzer(self.file_path)
                self.analyzer_type = 'apk'
            elif self.file_path.lower().endswith('.ipa'):
                self.analyzer = IpaAnalyzer(self.file_path)
                self.analyzer_type = 'ipa'
            else:
                self.finished_signal.emit(False, None, "Unsupported file type")
                return

            self.analyzer.set_progress_callback(self.emit_progress)
            success = self.analyzer.analyze()
            
            if success:
                self.finished_signal.emit(True, self.analyzer, self.analyzer_type)
            else:
                self.finished_signal.emit(False, None, self.analyzer.error)
        except Exception as e:
            self.finished_signal.emit(False, None, str(e))
            import traceback
            traceback.print_exc()

    def emit_progress(self, value, message):
        self.progress_signal.emit(value, message)

class OverlayWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(OverlayWidget, self).__init__(parent)
        self.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents, False)
        self.setAttribute(QtCore.Qt.WA_NoSystemBackground, False)
        
        # Auto-progress timer to prevent "stuck" feeling
        self.creep_timer = QtCore.QTimer(self)
        self.creep_timer.timeout.connect(self._on_creep_timer)
        self.creep_mode = False
        
        # Layer 1: Log (Bottom)
        self.log_widget = QtWidgets.QTextEdit(self)
        self.log_widget.setReadOnly(True)
        
        if platform.system() == 'Windows':
            log_font_size = "20px"
            card_width = 800
            loading_font = "36px"
            action_font = "20px"
        else:
            log_font_size = "13px"
            card_width = 500
            loading_font = "24px"
            action_font = "14px"
            
        self.log_widget.setStyleSheet(f"""
            QTextEdit {{
                background-color: #1a1a1a;
                color: #00ff00;
                border: none;
                font-family: "Courier New", monospace;
                font-size: {log_font_size};
                padding: 10px;
            }}
        """)
        
        # Layer 2: Dim/Blur (Middle)
        self.dim_widget = QtWidgets.QWidget(self)
        self.dim_widget.setStyleSheet("background-color: rgba(0, 0, 0, 150);")
        self.dim_widget.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        
        # Layer 3: Progress (Top)
        self.progress_container = QtWidgets.QWidget(self)
        self.progress_container.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        
        # Setup Progress Layout
        self.progress_layout = QtWidgets.QVBoxLayout(self.progress_container)
        self.progress_layout.setAlignment(QtCore.Qt.AlignCenter)
        
        self.progress_card = QtWidgets.QWidget()
        self.progress_card.setFixedWidth(card_width)
        self.progress_card.setStyleSheet("""
            QWidget {
                background-color: rgba(40, 40, 40, 240);
                border: 1px solid #555;
                border-radius: 10px;
            }
            QLabel {
                background-color: transparent;
                color: white;
                border: none;
            }
        """)
        
        card_layout = QtWidgets.QVBoxLayout(self.progress_card)
        card_layout.setContentsMargins(30, 30, 30, 30)
        
        self.loading_label = QtWidgets.QLabel("Analyzing...")
        self.loading_label.setStyleSheet(f"font-size: {loading_font}; font-weight: bold; margin-bottom: 10px;")
        self.loading_label.setAlignment(QtCore.Qt.AlignCenter)
        
        self.progress_bar = QtWidgets.QProgressBar()
        
        if platform.system() == 'Windows':
            self.progress_bar.setFixedHeight(30)
            pb_font_size = "18px"
        else:
            self.progress_bar.setFixedHeight(8)
            pb_font_size = "10px"
            
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                background-color: #444;
                border-radius: 4px;
                text-align: center;
                color: white;
                font-weight: bold;
                font-size: {pb_font_size};
            }}
            QProgressBar::chunk {{
                background-color: #007acc;
                border-radius: 4px;
            }}
        """)
        
        self.current_action_label = QtWidgets.QLabel("Initializing...")
        self.current_action_label.setStyleSheet(f"font-size: {action_font}; color: #aaa; margin-top: 5px;")
        self.current_action_label.setAlignment(QtCore.Qt.AlignCenter)
        
        card_layout.addWidget(self.loading_label)
        card_layout.addWidget(self.progress_bar)
        card_layout.addWidget(self.current_action_label)
        
        self.progress_layout.addWidget(self.progress_card)

    def resizeEvent(self, event):
        s = event.size()
        # Ensure full coverage
        self.log_widget.setGeometry(0, 0, s.width(), s.height())
        self.dim_widget.setGeometry(0, 0, s.width(), s.height())
        self.progress_container.setGeometry(0, 0, s.width(), s.height())
        
        # Ensure Z-Order (Lower is bottom)
        self.log_widget.lower()
        self.dim_widget.stackUnder(self.progress_container)
        self.progress_container.raise_()
        
        super(OverlayWidget, self).resizeEvent(event)

    def set_progress(self, value, message):
        # Always update message
        self.current_action_label.setText(message)
        self.log_text_append(f"> {message}")

        # Logic for progress bar
        current_val = self.progress_bar.value()
        
        # Reset if value is 0 (new analysis)
        if value == 0:
            self.progress_bar.setValue(0)
            self.creep_timer.stop() # Stop previous timer if any
            return

        # If new value is higher, jump to it
        if value > current_val:
            self.progress_bar.setValue(value)
        
        # If value is 100, stop creep
        if value >= 100:
            self.creep_timer.stop()
            self.progress_bar.setValue(100)
        elif value > 0 and not self.creep_timer.isActive():
            # Start creeping if not started
            self._start_creep()

    def _start_creep(self):
        # Start a slow timer to increment progress artificially
        # This prevents the "stuck" feeling
        self.creep_timer.start(500) # Check every 500ms

    def _on_creep_timer(self):
        val = self.progress_bar.value()
        if val < 95:
            # Slow down as we get higher
            # 0-50: fast
            # 50-80: medium
            # 80-95: slow
            
            should_increment = False
            import random
            
            if val < 50:
                should_increment = True # Always increment
            elif val < 80:
                should_increment = (random.random() > 0.3) # 70% chance
            else:
                should_increment = (random.random() > 0.7) # 30% chance
                
            if should_increment:
                self.progress_bar.setValue(val + 1)

    def log_text_append(self, text):
        self.log_widget.append(text)
        cursor = self.log_widget.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        self.log_widget.setTextCursor(cursor)
        
    def clear_log(self):
        self.log_widget.clear()


class MainForm(QtWidgets.QMainWindow):
    def __init__(self):
        super(MainForm, self).__init__()
        self.setWindowTitle("AppDetecter - Modern APK/IPA Analyzer")
        
        if platform.system() == 'Windows':
            self.resize(1600, 1100) # Windows specific large size
        else:
            self.resize(900, 600) # Mac default
            
        self.setAcceptDrops(True)
        
        self.init_ui()

    def load_icon(self, name):
        """Helper to load icons from Resources/icons/"""
        if getattr(sys, 'frozen', False):
            base_dir = sys._MEIPASS
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
        icon_path = os.path.join(base_dir, 'Resources', 'icons', f'{name}.svg')
        if os.path.exists(icon_path):
            return QtGui.QIcon(icon_path)
        return QtGui.QIcon() # Return empty icon if not found

    def init_ui(self):
        # Central Widget
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QtWidgets.QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0) # Full bleed

        # Stacked Layout to hold Drop Area and App Info
        self.stacked_widget = QtWidgets.QStackedWidget()
        self.main_layout.addWidget(self.stacked_widget)

        # 1. Drop Area Page
        self.drop_page = QtWidgets.QWidget()
        drop_layout = QtWidgets.QVBoxLayout(self.drop_page)
        drop_layout.setAlignment(QtCore.Qt.AlignCenter)
        
        self.drop_label = QtWidgets.QLabel("Drop APK / IPA File Here")
        self.drop_label.setAlignment(QtCore.Qt.AlignCenter)
        self.drop_label.setStyleSheet("""
            QLabel {
                font-size: 36px;
                color: #888;
                font-weight: bold;
            }
        """)
        
        self.sub_drop_label = QtWidgets.QLabel("or select File > Open from menu")
        self.sub_drop_label.setAlignment(QtCore.Qt.AlignCenter)
        self.sub_drop_label.setStyleSheet("font-size: 18px; color: #666;")
        
        # Try to load logo
        # For Window Icon: Handled in ApkDetecter.py globally
        # logo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Resources', 'logo.png')
        # if os.path.exists(logo_path):
        #    self.setWindowIcon(QtGui.QIcon(logo_path))

        drop_layout.addStretch()
        # Removed icon_graphic from display
        drop_layout.addWidget(self.drop_label)
        drop_layout.addWidget(self.sub_drop_label)
        drop_layout.addStretch()
        
        self.stacked_widget.addWidget(self.drop_page)

        # 2. App Info Page
        self.app_info_widget = AppInfoWidget()
        self.stacked_widget.addWidget(self.app_info_widget)

        # Overlay for Loading (Hidden by default)
        # Note: Parent is central_widget to cover everything inside it
        self.overlay = OverlayWidget(self.central_widget)
        self.overlay.hide()

        # Menu Bar
        # On macOS, we want the native global menu bar.
        # On Windows, user requested to remove it to match Mac's "clean window" look (since Mac has it in system bar).
        if platform.system() == 'Darwin':
            menubar = self.menuBar()
            file_menu = menubar.addMenu("File")
            
            open_action = QtWidgets.QAction("Open", self)
            open_action.setShortcut("Ctrl+O")
            open_action.setIcon(self.load_icon('open'))
            open_action.triggered.connect(self.open_file_dialog)
            file_menu.addAction(open_action)

            exit_action = QtWidgets.QAction("Exit", self)
            exit_action.setShortcut("Ctrl+Q")
            exit_action.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DialogCloseButton))
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)
            
            help_menu = menubar.addMenu("Help")
            about_action = QtWidgets.QAction("About", self)
            about_action.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_MessageBoxInformation))
            about_action.triggered.connect(self.show_about)
            help_menu.addAction(about_action)
        else:
            # For Windows (and others), we define actions but don't add them to a MenuBar
            # ensuring they can still be triggered via shortcuts or Toolbar if needed.
            open_action = QtWidgets.QAction("Open", self)
            open_action.setShortcut("Ctrl+O")
            open_action.setIcon(self.load_icon('open'))
            open_action.triggered.connect(self.open_file_dialog)

            exit_action = QtWidgets.QAction("Exit", self)
            exit_action.setShortcut("Ctrl+Q")
            exit_action.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DialogCloseButton))
            exit_action.triggered.connect(self.close)
            
            about_action = QtWidgets.QAction("About", self)
            about_action.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_MessageBoxInformation))
            about_action.triggered.connect(self.show_about)

        # Toolbar
        toolbar = QtWidgets.QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        if platform.system() == 'Windows':
            toolbar.setIconSize(QtCore.QSize(48, 48))
        else:
            toolbar.setIconSize(QtCore.QSize(32, 32)) # Default mac size
        self.addToolBar(toolbar)

        toolbar.addAction(open_action)

        # Clear Action
        clear_action = QtWidgets.QAction("Clear", self)
        clear_action.setIcon(self.load_icon('clear'))
        clear_action.setToolTip("Clear current analysis")
        clear_action.triggered.connect(self.clear_analysis)
        toolbar.addAction(clear_action)

        toolbar.addSeparator()

        # Export Action
        export_action = QtWidgets.QAction("Export", self)
        export_action.setIcon(self.load_icon('export'))
        export_action.setToolTip("Export analysis report")
        export_action.triggered.connect(self.export_report)
        toolbar.addAction(export_action)
        
        # Deep Scan Action
        deep_scan_action = QtWidgets.QAction("Deep Scan", self)
        deep_scan_action.setIcon(self.load_icon('scan'))
        deep_scan_action.setToolTip("Run deep scan (Slow)")
        deep_scan_action.triggered.connect(self.run_deep_scan)
        toolbar.addAction(deep_scan_action)

        # Add a spacer to push other items (if any)
        # empty_widget = QtWidgets.QWidget()
        # empty_widget.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        # toolbar.addWidget(empty_widget)
        
        # Status Bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")

    def resizeEvent(self, event):
        # Resize overlay to cover entire window content area
        self.overlay.resize(self.central_widget.size())
        super(MainForm, self).resizeEvent(event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
            self.drop_page.setStyleSheet("background-color: #2a2a2a;") # Highlight
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.drop_page.setStyleSheet("") # Reset

    def dropEvent(self, event):
        self.drop_page.setStyleSheet("")
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        for f in files:
            if f.lower().endswith('.apk') or f.lower().endswith('.ipa'):
                self.load_file(f)
                break

    def open_file_dialog(self):
        options = QtWidgets.QFileDialog.Options()
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open App File", "", "App Files (*.apk *.ipa);;APK Files (*.apk);;IPA Files (*.ipa);;All Files (*)", options=options)
        if fname:
            self.load_file(fname)

    def load_file(self, file_path):
        self.overlay.clear_log() # Clear previous logs
        self.overlay.show()
        self.overlay.raise_()
        self.overlay.set_progress(0, f"Initializing analysis for {os.path.basename(file_path)}...")
        self.status_bar.showMessage(f"Analyzing {file_path}...")

        # Start Thread
        self.thread = AnalysisThread(file_path)
        self.thread.progress_signal.connect(self.update_progress)
        self.thread.finished_signal.connect(self.analysis_finished)
        self.thread.start()

    def update_progress(self, value, message):
        self.overlay.set_progress(value, message)
        self.status_bar.showMessage(message)

    def analysis_finished(self, success, analyzer, analyzer_type):
        self.overlay.hide()
        
        if success:
            self.stacked_widget.setCurrentWidget(self.app_info_widget)
            self.app_info_widget.update_data(analyzer_type, analyzer)
            self.status_bar.showMessage(f"Loaded: {os.path.basename(self.thread.file_path)}")
            
            # Store data for export
            self.current_analyzer_info = analyzer.get_basic_info()
            # Add more details if needed
            self.current_analyzer_info['full_details'] = analyzer.info
            
        else:
            self.stacked_widget.setCurrentWidget(self.drop_page)
            error_msg = analyzer_type if analyzer_type else "Error"
            QtWidgets.QMessageBox.critical(self, "Analysis Error", str(error_msg))
            self.status_bar.showMessage("Analysis failed.")

    def show_about(self):
        QtWidgets.QMessageBox.about(self, "About", 
            "<h3>AppDetecter</h3>"
            "<p>A modern tool for analyzing Android (APK) and iOS (IPA) applications.</p>"
            "<p>Refactored by AYL.</p>"
        )

    def clear_analysis(self):
        self.stacked_widget.setCurrentWidget(self.drop_page)
        self.status_bar.showMessage("Ready")
        self.setWindowTitle("AppDetecter - Modern APK/IPA Analyzer")

    def export_report(self):
        if self.stacked_widget.currentWidget() != self.app_info_widget:
            QtWidgets.QMessageBox.warning(self, "Export", "No analysis data to export. Please load an app first.")
            return

        options = QtWidgets.QFileDialog.Options()
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Report", "report.json", "JSON Files (*.json);;Text Files (*.txt)", options=options)
        
        if file_path:
            try:
                if hasattr(self, 'current_analyzer_info'):
                    import json
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(self.current_analyzer_info, f, indent=4, ensure_ascii=False)
                    self.status_bar.showMessage(f"Report exported to {file_path}")
                else:
                     QtWidgets.QMessageBox.warning(self, "Export", "Data not available for export.")

            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Export Error", str(e))

    def run_deep_scan(self):
        if self.stacked_widget.currentWidget() != self.app_info_widget:
            QtWidgets.QMessageBox.warning(self, "Deep Scan", "Please load an app first.")
            return

        # Check if we have an analyzer instance
        if hasattr(self, 'thread') and self.thread.analyzer:
             analyzer = self.thread.analyzer
             
             # Determine type
             apk_obj = None
             ipa_path = None
             
             if hasattr(analyzer, 'apk'):
                 apk_obj = analyzer.apk
             elif hasattr(analyzer, 'file_path') and analyzer.file_path.lower().endswith('.ipa'):
                 ipa_path = analyzer.file_path
                 # Pass the found binary path if available
                 if hasattr(analyzer, 'binary_path'):
                     # We can't pass it directly to DeepScanner constructor as currently defined,
                     # but we can improve DeepScanner or DeepScanThread.
                     # Let's pass the analyzer itself to DeepScanThread instead?
                     pass
             
             if apk_obj or ipa_path:
                 self.overlay.show()
                 self.overlay.raise_()
                 self.overlay.set_progress(0, "Starting Deep Scan...")
                 
                 # Run in a new thread to avoid blocking UI
                 self.scan_thread = DeepScanThread(apk_obj, ipa_path, analyzer)
                 self.scan_thread.progress_signal.connect(self.update_progress)
                 self.scan_thread.finished_signal.connect(self.deep_scan_finished)
                 self.scan_thread.start()
             else:
                 QtWidgets.QMessageBox.warning(self, "Deep Scan", "Could not determine scan target (APK/IPA).")
        else:
             QtWidgets.QMessageBox.warning(self, "Deep Scan", "Analysis session expired. Please reload the app.")

    def deep_scan_finished(self, results):
        self.overlay.hide()
        self.status_bar.showMessage("Deep Scan Completed")
        
        # Show results in a new dialog or tab
        # For now, let's use a simple dialog with tabs
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Deep Scan Results")
        # Remove the context help button (?)
        dlg.setWindowFlags(dlg.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
        
        if platform.system() == 'Windows':
            dlg.resize(1200, 1000)
        else:
            dlg.resize(600, 500)
        
        layout = QtWidgets.QVBoxLayout(dlg)
        tabs = QtWidgets.QTabWidget()
        
        # Helper to add tab
        def add_result_tab(name, data_list):
            widget = QtWidgets.QWidget()
            vbox = QtWidgets.QVBoxLayout(widget)
            text_edit = QtWidgets.QTextEdit()
            text_edit.setReadOnly(True)
            if data_list:
                text_edit.setText("\n".join(data_list))
            else:
                text_edit.setText("No entries found.")
            vbox.addWidget(text_edit)
            tabs.addTab(widget, f"{name} ({len(data_list)})")
            
        add_result_tab("URLs", results.get("urls", []))
        add_result_tab("IPs", results.get("ips", []))
        add_result_tab("Strings", results.get("sensitive_strings", []))
        add_result_tab("Anti-Debug", results.get("anti_debug", []))
        add_result_tab("Crypto", results.get("crypto", []))
        
        layout.addWidget(tabs)
        
        # Button Box
        btn_layout = QtWidgets.QHBoxLayout()
        
        export_btn = QtWidgets.QPushButton("Export Results")
        export_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DialogSaveButton))
        export_btn.clicked.connect(lambda: self.export_deep_scan_results(results, dlg))
        btn_layout.addWidget(export_btn)
        
        btn_layout.addStretch()
        
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        
        dlg.exec_()

    def export_deep_scan_results(self, results, parent_dlg):
        options = QtWidgets.QFileDialog.Options()
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(parent_dlg, "Export Deep Scan Results", "deep_scan_results.zip", "ZIP Files (*.zip)", options=options)
        
        if file_path:
            try:
                import zipfile
                
                with zipfile.ZipFile(file_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                    # Helper to write list to file in zip
                    def write_list_to_zip(name, data_list):
                        content = ""
                        if data_list:
                            content = "\n".join(data_list)
                        else:
                            content = "No entries found."
                        zf.writestr(f"{name}.txt", content)

                    write_list_to_zip("URLs", results.get("urls", []))
                    write_list_to_zip("IPs", results.get("ips", []))
                    write_list_to_zip("Strings", results.get("sensitive_strings", []))
                    write_list_to_zip("Anti-Debug", results.get("anti_debug", []))
                    write_list_to_zip("Crypto", results.get("crypto", []))

                QtWidgets.QMessageBox.information(parent_dlg, "Export", f"Results exported to {file_path}")
            except Exception as e:
                QtWidgets.QMessageBox.critical(parent_dlg, "Export Error", str(e))

