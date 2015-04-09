__author__ = 'Andy'
from distutils.core import setup
import py2exe
import sys

#this allows to run it with a simple double click.
sys.argv.append('py2exe')

py2exe_options = {
        "includes": ["sip"],
        "dll_excludes": ["MSVCP90.dll",],
        "compressed": 1,
        "optimize": 2,
        "ascii": 0,
        "bundle_files": 1,
        }

setup(
      name = 'PyQt Demo',
      version = '1.0',
      windows = ['ApkDetecter.py',],
      zipfile = None,
      options = {'py2exe': py2exe_options}
      )
