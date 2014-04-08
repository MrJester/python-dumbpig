from distutils.core import setup

from dumbpig import *

setup(
    name = 'python-dumbpig',
    packages = ['dumbpig'],
    version = dumbpig.__version__,
        description = 'A python class for dumbpig to perform rule scans and '
                      'access results',
        author = dumbpig.__author__,
        author_email = dumbpig.__author_email__,
        license ='gpl-3.0.txt',
        url = 'https://github.com/MrJester/python-dumbpig',
        download_url = 'https://github.com/MrJester/python-dumbpig/tarball/0.0.1',
        classifiers = [],
    )