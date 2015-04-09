#-*- coding:utf-8-*-
__author__ = 'Andy'

import sys
from cx_Freeze import setup, Executable

base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(
      name = 'PyQt Demo',
      version = '1.0',
      description = 'Sample cx_freeze PyQt4 script',
      options = {'build_exe': {"includes":"atexit"}},
      executables =[Executable("ApkDetecter.py", base = base)]
)
