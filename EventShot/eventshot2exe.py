from distutils.core import setup
import py2exe, sys, os

sys.argv.append('py2exe')

setup(
    options = {'py2exe': {'bundle_files': 3}},
    console = [{'script': "EventShot.py"}],
    zipfile = None,
)