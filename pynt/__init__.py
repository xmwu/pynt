'''
Python Network Test (PyNT) provides a list of tools that help test engineers with common tasks. The core modules is a shim layer interacting with network devices, servers, testers, and other common cloud objects. 
'''
import sys
try:
    import os
except ImportError: # pragma: no cover
    err = sys.exc_info()[1]
    raise ImportError(str(err) + 'Not all modules were found. Please check Operating System and Python Modules.')

__author__ = 'Sean Wu'
__email__ = 'seanwu@gmail.com'
__copyright__ = 'Copyright 2003-2015, xkey.org'
__version__ = '0.1'
__revision__ = ""
#__all__ = ['ExceptionPyNT', 'new', 'cmd', '__version__', '__revision__']
