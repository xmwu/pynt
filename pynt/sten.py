'''
A STEN - Simplified TEstcase Notation - parser
Process YAML based STEN file and generate necessary testscripts
'''

import time
import yaml
import datetime
import os
import sys
import getopt
import re
import socket, struct
import binascii

__author__ = 'Sean Wu'
__email__ = 'xwu@xkey.org'
__copyright__ = 'Copyright 2003-2016, XKEY'
__version__ = '0.1'
__revision__ = ""
#__all__ = ['ExceptionPyNT', 'new', 'cmd', '__version__', '__revision__']

PY3 = (sys.version_info[0] >=3)
PROMPT = '[>#%\$](?:\033\[0m \S*)?\s*$'
#PROMPT = '[>#%\$] $'
#V4Addr= "(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
ip4Addr = "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
hex4 = '[A-Fa-f\d]{0,4}'
ip6Addr = "(?:(?:"+hex4+":{1,2}?){2,7}(?:" + ip4Addr + "|" + hex4 + ")?)"
ipAddr = "(" + ip4Addr + "|" + ip6Addr + ")"

reIp4Addr = re.compile(ip4Addr)
reIp6Addr = re.compile(ip6Addr)
reIpAddr = re.compile(ipAddr)


class sten(object):
    '''Main class for STEN parser
    '''
    def usage():
        print "sten -f <test.sten>"

    def __init__(self, **kargs):
        self.fname = kargs.pop('file', "example.sten")
        self.dut = kargs.pop('dut', 0)                   # Device under Test
        self.retries = kargs.pop('tries', 8)               # retries to connect
        # private
        if(not os.path.isfile(self.fname)) :
            self.usage()
            return 0

        try :
            f = open(self.fname)
        except ImportError:
            pass

        self.sten = yaml.load(f)
        print yaml.dump(self.sten)
        print "=" * 60
        print self.sten['testcases']

        return

            
        if(self.conn_proto == 'ssh') :
            self.h = pxssh.pxssh()
            #self.h.logfile = sys.stdout #debug
            self.h.PROMPT = PROMPT
            self.h.login(self.host, self.user, self.passwd, 
                    auto_prompt_reset=False,
                    original_prompt = PROMPT
                    )
            self.mode_cli()
            self.cli("show version")
            print self.h.before
        else :
            print "the conn_proto is not supported\n"

if __name__ == "__main__" :
    sten = sten(file="/Users/xwu/dev/gitlab/vmxaws.sten")

