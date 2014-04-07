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
        download_url = 'https://github.com/peterldowns/mypackage/tarball/0.1', # I'll explain this in a second
        keywords = ['dumbpig', 'snort', 'ids', 'ips', 'security'],
        classifiers = [],
    )