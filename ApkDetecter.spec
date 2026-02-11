# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

import os
import sys

# Ensure libs path is included
sys.path.insert(0, os.path.abspath('libs'))

a = Analysis(
    ['ApkDetecter.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('Resources', 'Resources'),
        ('libs', 'libs'),
        ('Core', 'Core'),
        ('GUI', 'GUI'),
        ('AnalysisCSN', 'AnalysisCSN'),
        ('AnalysisDEX', 'AnalysisDEX'),
        ('AnalysisXML', 'AnalysisXML'),
    ],
    hiddenimports=[
        'PyQt5', 
        'cryptography', 
        'asn1crypto', 
        'androguard', 
        'click', 
        'colorama', 
        'loguru',
        'xml.etree.ElementTree',
        'zipfile'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ApkDetecter',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False, 
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='Resources/logo.png'
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ApkDetecter',
)

app = BUNDLE(
    coll,
    name='ApkDetecter.app',
    icon='Resources/AppIcon.icns',
    bundle_identifier='com.apkdetecter.app',
    info_plist={
        'NSHighResolutionCapable': 'True',
        'CFBundleShortVersionString': '1.0.0',
        'CFBundleVersion': '1.0.0',
    },
)
