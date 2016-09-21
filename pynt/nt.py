'''This class extends pexpect.spawn to simulate device handles and 
related operation methods
TODO - exception handling

Environment Variables Supported and their Default Values

       * PYNT_USER:         pynt
       * PYNT_PASSWORD:     PyNT123
       * PYNT_ROOTPW:       PyNt!2#
       * PYNT_SSH_KEY:      ~/.ssh/id_rsa
       * PYNT_LOGFILE:      nt.log
       * PYNT_VMX_LIC:      ''
       * PYNT_AWS_KEYFILE:  ''
       * PYNT_AWS_KEYNAME:  ''
       * PYNT_AWS_AMI_VMX:  ami-2cbec54c # Mar 27, 2016
       * PYNT_AWS_AMI_LNX:  ami-06116566 # Ubuntu 14.04
       * PYNT_AWS_LNX_TYPE: t2.micro
       * PYNT_AWS_VMX_TYPE: m4.xlarge
       * PYNT_AWS_REGION:   us-west-1
       * PYNT_AWS_VPC_NAME: w01
       * PYNT_AWS_PLACE_GROUP_NAME: ''

'''
from __future__ import print_function
import time,datetime
import os,sys,re
import getopt,pexpect
import socket, struct, fcntl, threading
import binascii,logging
import xml.etree.ElementTree as ET
import pprint

try:
    import pexpect.pxssh
    from pysnmp.hlapi import *
except ImportError: # pragma: no cover
    err = sys.exc_info()[1]
    raise ImportError(str(err) + '''Not all modules were found. Please check Operating System and Python Modules.
''')

__author__ = 'Sean Wu'
__email__ = 'seanwu@gmail.com'
__copyright__ = 'Copyright 2003-2016, xkey.org'
__version__ = '0.1'
__revision__ = ""
#__all__ = ['ExceptionPyNT', 'new', 'cmd', '__version__', '__revision__']

PY3 = (sys.version_info[0] >=3)
#PROMPT = '[>#%\$](?:\033\[0m \S*)?\s*$'
PROMPT = '[>#%\$] $'
PROMPT_MORE = '^ --More--[\s\b]*';
ip4Addr = "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
hex4 = '[A-Fa-f\d]{0,4}'
ip6Addr = "(?:(?:"+hex4+":{1,2}?){2,7}(?:" + ip4Addr + "|" + hex4 + ")?)"
ipAddr = "(" + ip4Addr + "|" + ip6Addr + ")"

reIp4Addr = re.compile(ip4Addr)
reIp6Addr = re.compile(ip6Addr)
reIpAddr = re.compile(ipAddr)

pp = pprint.PrettyPrinter(indent=4)

ntini = {}
def _get_env():
    ini_values = {
        'USER':         'pynt',
        'PASSWORD':     'PyNT123',
        'ROOTPW':       'PyNt!2#',
        'SSH_KEY':      '~/.ssh/id_rsa',
        'LOGFILE':      'nt.log',
        'VMX_LIC':      None,
        'AWS_KEYFILE':  '',
        'AWS_KEYNAME':  '',
        'AWS_AMI_VMX':  'ami-2cbec54c', # Mar 27, 2016
        'AWS_AMI_LNX':  'ami-06116566', # Ubuntu 14.04
        'AWS_LNX_TYPE': 't2.micro',
        'AWS_VMX_TYPE': 'm4.xlarge',
        'AWS_REGION':   'us-west-1',
        'AWS_VPC_NAME': 'w01',
        'AWS_PLACE_GROUP_NAME': '',
    }
    for key, value in ini_values.iteritems():
        ntini[key] = os.environ.get('PYNT_' + key, value)
        if key in ('SSH_KEY', 'AWS_KEYFILE'):
            m = re.search("^~/", ntini[key])
            if m:
                ntini[key] = os.path.expanduser(ntini[key])

_get_env()

def ntlogger():
    logLevel = logging.DEBUG
    nlog = logging.getLogger('pynt')
    nlog.setLevel(logLevel)
    #nlog.setLevel(logLevel)
    fh = logging.FileHandler(ntini['LOGFILE'])
    fh.setLevel(logLevel)
    ch = logging.StreamHandler()
    ch.setLevel(logLevel)
    ntFmt = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    fh.setFormatter(ntFmt)
    ch.setFormatter(ntFmt)
    nlog.addHandler(fh)
    nlog.addHandler(ch)
    return nlog

nlog = ntlogger()

# Utility methods
def ip2decimal(ip, family=0) :
    '''
    Convert IPv4 and IPv6 to Integer, with family optional
    '''
    if(family == socket.AF_INET or reIp4Addr.match(ip)) :
        return struct.unpack("!L", socket.inet_aton(ip))[0]
    elif(family == socket.AF_INET6 or reIp6Addr.match(ip)) :
        return  int(binascii.hexlify(socket.inet_pton(socket.AF_INET6, ip)), 16)
    else :
        ntlog("Invalid IP address " + ip)

def decimal2ip(number, family=0) :
    '''
    Convert integer to IPv4 or IPv6 address, here family might be useful
    esp when a number derived from ::1.1.1.1
    '''
    if(number > 4294967295) :
        return socket.inet_ntop(socket.AF_INET6, binascii.unhexlify('%032x' % number))
    else :
        return socket.inet_ntoa(struct.pack('!L', number))

def get_mask(base):
    '''
    Return masks for one or more IP blocks in bit-length format
    '''
    if type(base) is list:
        masks = []
        for b in base:
            masks.append(_get_mask_single(b))
        return masks
    else:
        return _get_mask_single(base)

def _get_mask_single(base):
    if type(base) is not str or "/" not in base:
        ntlog("get_mask: invalid base %s and the type is %s" % (base, type(base)), level=logging.ERROR)
        return None
    parts = base.split("/")
    return int(parts[1])


def get_network(ips):
    '''
    Returns the network b lock for an IP "address/netmask".
    '''
    masks = get_mask(ips)
    networks = []
    if type(ips) is str:
        ips = [ips]
        masks = [masks]
    for idx in range(len(ips)):
        bits = 32
        if reIp6Addr.match(ips[idx]):
            bits = 128
        ip = ip2decimal(strip_mask(ips[idx]))
        ntwk = ip >> (bits - masks[idx]) << (bits - masks[idx])
        networks.append(decimal2ip(ntwk) + "/" + str(masks[idx]))

    if len(networks) == 1:
        return networks[0]
    else:
        return networks

def strip_mask(ips):
    '''
    Accepts one or more IP blocks and returns them with their netmask removed
    '''
    if type(ips) is str:
        return ips.split("/")[0]
    elif type(ips) is list:
        addrs = []
        for ip in ips:
            addrs.append(ntwk.split("/")[0])
        return addrs
    else:
        ntlog("strip_mask: invalid ips", level=logging.ERROR)
        return None

def get_subnets(base, mask=None, num=None, offset=0):
    '''
    Create and returns subnets derived from a network address or block
        * *base* network address/block to start from
        * *mask* network mask length, default is to derive from num
        * *num* number of subnets to be returned, default is return all
        * *offset* offset added to subnet network address, default is 0, 
    '''
    if mask is None and num is None:
        ntlog("Base network needs netmask unless NUM and MASK sepcified",
            level=logging.ERROR)
        return None
    bits = 32 # IPv4
    if ":" in base:
        bits = 128 # IPv6
    base_mask = get_mask(base)
    if num is None:
        if mask < base_mask:
            ntlog("Invalid netmasks or mask requested is larger than base",
                level=logging.ERROR)
            return None
        num = 2 ** (mask - base_mask)
    if mask is None:
        hosts_per_subnet = 2**(bits-base_mask) / num
        if num < 1 or hosts_per_subnet < 1:
            ntlog("Invalid netmask or number", level=logging.ERROR)
            return None
        mask = bits - int(log(hosts_per_subnet) / log (2))
    base_d = ip2decimal(strip_mask(get_network(strip_mask(base)+"/"+str(mask))))
    mask_d = 2 ** (bits - mask) # Python supports L well
    offset %= mask_d # no special need for negative offset
    subnets = []
    for idx in range(num):
        ip = base_d + idx * mask_d + offset
        subnets.append(decimal2ip(ip) + "/" + str(mask))

    return subnets

def ip_add(ip, offset):
    '''
    return IP + offerset. Supports both IPv4 and IPv6, offset is an integer
    '''
    family = chk_ip(ip)
    if not family:
        ntlog("Invalid IP", level=logging.ERROR)
        return None
    return decimal2ip(ip2decimal(ip) + int(offset), family=family)

def chk_ip(ip):
    '''
    return family of ip in socket.AF_INET for IPv4 and socket.AF_INET6 for 
    IPv6. otherwise, return 0
    '''
    if reIp6Addr.match(ip):
        return socket.AF_INET6
    elif reIp4Addr.match(ip) :
        return socket.AF_INET
    else:
        return 0

def sort_ip(ips):
    '''Get a list of IPv4 addresses, and return a list of sorted IPs
    if there is an invalid IPv4 element, return False
    '''
    result = []
    valid = True
    if type(ips) is not list:
        valid = False
    for ip in ips:
        if chk_ip(ip) != socket.AF_INET :
            valid = False
            break
    if valid:
        return sorted(ips, key=lambda ip: struct.unpack("!L", 
            socket.inet_aton(ip))[0])
    else:
        ntlog("sort_ip: only list of IPv4 addresses is supported. Aborting...",
            logging.ERROR)
        return valid


def ntlog(msg, level=logging.INFO) :
    '''
    Standard logging with timestamp, level. facility and user TBD
    '''
    nlog.log(level, msg)

def sleep(interval):
    '''
    Sleep for interval seconds
    '''
    if type(interval) is not int or interval > 1800:
        ntlog("interval needs to be an integer less than 1800 seconds",
            level=logging.WARNING)
        return False
    ntlog("Sleeping for %d seconds " % interval)
    for sec in range(interval):
        time.sleep(1)
        #print('.', end="", flush=True)
        sys.stdout.write(".")
        sys.stdout.flush()
    sys.stdout.write("\n")
    sys.stdout.flush()
    return True

def get_dict_leaf(dictionary, path, separator='.'):
    '''extract a leaf of chained dictionary and keys joined with 
    separators'''
    paths = path.split(separator)
    root = dictionary
    for idx in range(len(paths)):
        key = paths[idx]
        if key.isdigit():
            key = int(key)
        if (type(root) is dict and key in root) or \
            (type(root) is list and key < len(root)):
            root = root[key]
        else:
            ntlog("get_dict_leaf does not contain key %s" % str(key), logging.ERROR)
            return None
    return root
    
def chk_host_port(host, port, interval=5, timeout=30, family=socket.AF_INET, prompt=None):
    '''Check host:port reacheability'''
    ts_start = time.time()
    hostup = False
    svcup = False
    while time.time() - ts_start <= timeout:
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((host, port))
            ntlog("Host %s is reachable at port %d" %(host, port))
            hostup = True
            if prompt is not None:
                data = s.recv(80)
                if prompt in data:
                    ntlog("Service is up with banner of " + prompt)
                    svcup = True
                    s.close()
                    break
                else:
                    msg += "Service is down expecting banner of " + prompt
            else :
                s.close()
                break
        except socket.error as e:
            ntlog("Host %s is not reachable at port %d." % (host, port))
            if e != socket.timeout:
                ntlog("Exception from socket: %s" % sys.exc_info()[0])
            s.close()
            s = None
        sleep(interval)
    if not hostup:
        ntlog("Host %s is not reachable at port %d before %d seconds timeout" %  (host, port, timeout))
    elif prompt is None: 
        return hostup
    elif not svcup:
        ntlog("Host %s is reachable at port %d, but service %s is not up before %d seconds timeout" % (host, port, prompt, timeout))
        return svcup
    else:
        ntlog("Service %s is up" % prompt)
        return svcup
    return hostup
        
def get_interface_ip(ifname="eth0"):
    '''Get local Linux interface IP address'''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915, # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
        )[20:24])

class ExceptionPyNT(Exception) :
    ''' Raised for PyNT exceptions.
    '''



class Timer(object):
    '''A simple Timer, ideal for recording event of sequence'''
    def __init__(self, name = "Unknown Event"):
        self.name = name
        self.steps = [{'Step': 'Start', 'Datetime': 
            datetime.datetime.now()}]
    
    def update(self, name = None):
        if name is None:
            name = str(len(self.steps))
        self.steps.append({'Step': name, 'Datetime': datetime.datetime.now()})

    def stop(self, name = "Stop"):
        self.steps.append({'Step': name, 'Datetime': datetime.datetime.now()})
        self.log()

    def log(self):
        msg = "\nEvent %s has a total of %d steps and was completed in %s\n" % \
            (self.name, len(self.steps), 
            (self.steps[-1]['Datetime'] - self.steps[0]['Datetime']),
            )
        for stepid in range(len(self.steps)):
            step = self.steps[stepid]
            elapsed = 0
            if stepid != 0:
                elapsed = step['Datetime'] - self.steps[stepid - 1]['Datetime']
            msg += "Step %d %s: Time: %s Elapsed: %s\n" % (stepid, 
                step['Step'], step['Datetime'], elapsed)
        ntlog(msg)
                
class NT(object):
    '''Main class interface for PyNT object with the following attributes, 
    of which only **host** is requried. Not directly inherited from pexpect,
    so that it may be easily modified to use other underlying connection 
    modules, such as PyEZ

        * **host** : An IP or hostname for the entity
        * *user* : default user is pynt, or ENV PYNT_USER.
        * *password* : default password is PyNT123 or ENV PYNT_PASSWORD
        * *rootpw*: default root password is PyNt!2# or ENV PYNT_ROOTPW
        * *os* : operating system with default as junos
        * *timeout* : login timeout with default of 30 seconds
        * *cmd_timeout* : command timeout with default of 60 seconds
        * *conn_proto* : Connection protocol, only *ssh* and *telnet* is supported now
        * *hostlog* : Log filename for this host. The default is *host.log* with host being the provided argument.
        * *ssh_key* : ssh private key for login, it overrides password

    The following argument is not common
        * *host1* : Attempts to make second connection to backup RE. Only valid for junos devices. The default is host1 with host being the provided argument
        * *commitsync* : 0 or 1. commit synchronization for commit in config mode
        * *retries* : number of retries for login with default of 8
        * *auto_prompt_reset* : pass to pexpect

    '''
    # Global Variables
    PROMPT = '[>#%\$](?:\033\[0m \S*)?\s*$'
    PROMPT_MORE='^---?\(?[^)]*?[Mm]ore[^)]*\)?---?\s*'
    CMD_TIMEOUT = 300
    def __init__(self, host, **kargs):
        # instance variable
        self.host = host                    # required
        self.user = kargs.pop('user', ntini['USER'])     #SECURITY
        self.passwd = kargs.pop('password', ntini['PASSWORD']) # SECURITY
        self.rootpw = kargs.pop('rootpw', ntini['ROOTPW'])   # SECURITY
        self.os = kargs.pop('os', 'junos').lower()       # OS
        self.tag = kargs.pop('tag', "R")                 # alias like r1
        self.conn_proto = kargs.pop('conn_proto', 'ssh') # ssh/telnet
        self.login_enable = kargs.pop('login_enable', True) # auto login
        self.port = kargs.pop('port', None)
        if self.conn_proto == 'ssh':
            self.xfer_proto = 'scp'
            if self.port is None:
                self.port = 22
        elif self.conn_proto == 'telnet':
            self.xfer_proto = "ftp"
            if self.port is None:
                self.port = 23
        self.timeout = kargs.pop('timeout', 30)          # login timeout
        self.cmd_timeout = kargs.pop('cmd_timeout', 60)  # command timeout
        self.host_log = kargs.pop('host_log', self.host+'.log')   # name if not host
        self.ssh_key = kargs.pop('ssh_key', None) # 
        self._curr_mode = kargs.pop('mode', 'shell') #cli|config|vty|netconf|junoscript
        self.host1 = kargs.pop('host1', self.host+"1")        # if dual_re
        self.commitsync = kargs.pop('commit_synchronize', 0) 
        self.dut = kargs.pop('dut', 0)                   # Device under Test
        self.retries = kargs.pop('tries', 8)               # retries to connect
        self.auto_prompt_reset = kargs.pop('auto_prompt_reset', False)
        # private
        self._old_mode = self._curr_mode
        self.screen = True

        if(self.conn_proto == 'ssh') :
            if self.login_enable :
                self.login()
            if self.os == 'junos':
                self.cmd("cli")
                self.cmd("set cli screen-length 0")
                self._old_mode = self._curr_mode
                self._curr_mode = "cli"
        else :
            ntlog("the conn_proto is not supported\n")

    def login(self):
        retry = True
        attempts = 3
        interval = 15
        while(retry):
            try:
                self.h = pexpect.pxssh.pxssh(
                    options={"StrictHostKeyChecking": "no", 
                    "UserKnownHostsFile": "/dev/null"})
                self.h.logfile_read = sys.stdout #debug
                self.h.PROMPT = NT.PROMPT
                self.h.login(self.host, self.user, self.passwd, 
                    ssh_key=self.ssh_key,
                    auto_prompt_reset=self.auto_prompt_reset,
                    original_prompt = NT.PROMPT,
                )
                retry=False
                break
            except pexpect.pxssh.ExceptionPxssh as e:
                if e.value == "could not synchronize with original prompt":
                    ntlog("ssh login not sync with prompt, retry again " + \
                        "after %d seconds" % interval)
                    self.h.close()
                    attempts -= 1
                    sleep(interval)
                else:
                    retry = False
                    raise
        return True

    def sendline(self, s):
        return self.h.sendline(s)

    def send(self, s):
        return self.h.send(s)

    def expect(self, pattern, timeout=-1, searchwindowsize=-1, async=False):
        return self.h.expect(pattern, timeout, searchwindowsize, async)

    def set_xfer_proto(self, proto, ftp_port = 21, ftp_passive = True):
        ''' 
        Set file transfer protocols to either ssh or ftp. 
        if conn_proto is ssh, the default is scp.
        TODO - ftp support is to be added
        '''
        if proto == 'scp':
            self.xfer_proto = proto
        elif proto == "ftp":
            self.xfer_proto = proto
            self.ftp_port = ftp_port
            self.ftp_passive = ftp_passive 
        else:
            ntlog("unable to set file transfer protocol %s" % proto, 
                level=logging.ERROR)

    def get_dut(self) :
        return self.dut

    def get_tag(self) :
        return self.tag

    def get_os(self) :
        '''Return OS type of the object'''
        return self.os

    def mode(self, mode, target=None):
        '''
        JUNOS devices have several different modes of operation
        cli is the hub, with access to vty, shell, config
        target is only valid with vty mode for pfe target identification 
        string, like fpc0
        '''
        if self._curr_mode == mode:
            self._old_mode = self._curr_mode
            self._curr_mode = mode
            return True
        # return to CLI as hub
        if self._curr_mode != "cli":
            self._cmd_single("exit")
        # start to switch to new mode
        if mode == "cli":
            self._cmd_single("set cli screen-length 0")
            pass
        elif mode == "config":
            self._cmd_single("configure")
        elif mode == "shell":
            self._cmd_single("start shell")
        elif mode == "vty":
            if target is None:
                ntlog("vty targeted not specified, failed to change to vty")
                return False
            else:
                self._cmd_single("start shell pfe network %s" % target)
        self._old_mode = self._curr_mode
        self._curr_mode = mode
        return True

    def su(self, rootpw=None):
        '''enter su mode either with root password passed via API
        if None passed, use default root password of the NT object'''
        if rootpw is None:
            if self.rootpw is not None:
                rootpw = self.rootpw
            else:
                ntlog("Root password not set, aborting...", logging.ERROR)
                return False
        mode_curr = self._curr_mode
        if mode_curr != "shell":
            self.mode("shell")
        self.sendline("su -")
        self.expect("Password:")
        self.sendline(rootpw)
        index = self.expect(["su: Authentication failure", "su: Sorry", 
            self.PROMPT, pexpect.EOF, pexpect.TIMEOUT])
        if index == 0 or index == 1:
            ntlog("Password error", logging.WARNING)
            return False
        if index == 2 or index == 3:
            return True

    def mode_cli(self) :
        '''
        alias of device.mode("cli")
        '''
        # change mode to CLI, period
        #self._old_mode = self._curr_mode
        #self._curr_mode = "cli"
        self.mode("cli")


    def _mode_cli(self) :
        # internal routine, change to cli temporary
        if(self._old_mode != "cli") :
            self.h.sendline("cli")
            self.h.prompt()

    def _mode_restore(self, new_mode="cli") :
        return self.mode(self._old_mode)

    def cli(self, cmd, timeout=CMD_TIMEOUT) :
        '''
        Alias of device.cmd(cmd, mode="cli")
        '''
        return self.cmd(cmd, mode="cli", timeout=timeout)

    def cmd(self, cmd, mode=None, xml="false", timeout=CMD_TIMEOUT, xmlns=False) :
        '''
        Execute a single command if a string is passed. If a list is provided
        via cmd arguments, it executes all commands one by one
        xml supports the following
        - xpath if mode is cli. Returns (list of) ElementTree.Element
        - true if mode is cli. Returns (list of) xml in text
        xmlns removes non-junos namespace if False, which is the default
        '''
        mode_restore = 0
        output = []
        if mode is not None:
            self.mode(mode)
            mode_restore = 1
        if type(cmd) is list:
            for onecmd in cmd:
                output.append(self._cmd_single(onecmd, xml, timeout, xmlns))
        else:
            output = self._cmd_single(cmd, xml, timeout, xmlns)
        if mode_restore :
            self._mode_restore()
        return output

    def _cmd_single(self, cmd, xml="false", timeout=CMD_TIMEOUT, xmlns=False):
        if self.os == "junos" and self._curr_mode == "cli" and xml != "false":
            cmd += " | display xml"
        try:
            self.h.sendline(cmd)
            prompt_pattern = [PROMPT, PROMPT_MORE]
            while True :
                idx = self.h.expect(prompt_pattern, timeout = timeout)
                if idx == 0:
                    break
                elif idx == 1:
                    self.h.send(" ")
        except:
            ntlog("command failed with exception: %s" % sys.exc_info()[0],
                level = logging.ERROR)
        # had to remvoe first and last line
        output = "\n".join(self.h.before.split("\r\n")[1:-1])
        if xml == "xpath":
            if xmlns is False:
                # a hack to remove non junos namespace
                output = re.sub(' xmlns="[^"]+"', '', output)
            return ET.fromstring(output)
        elif xml == "true":
            return output
        else:
            return output

    def commit(self, sync=None, timeout=CMD_TIMEOUT):
        '''
        * *sync* 1 or 0, and overrides device.commitsync for this operation.

        user always has option to pass special argument.
        TODO: add support for commit full, commit and-quit and etc
        '''
        cs = self.commitsync
        if sync is not None:
            cs = sync
        cmd = "commit"
        if cs :
            cmd += " synchronize"
        self.mode("config")
        result = True
        exRaised = False
        pattern=[PROMPT, 'error']
        try:
            self.h.sendline(cmd) # + " and-quit")
            idx = self.h.expect(pattern, timeout = timeout)
            if idx == 1:
                result = False
        except:
            result = False
            exRaised = True
            ntlog("Commit failed " + sys.exc_info()[0], level=logging.ERROR)
        if not result and not exRaised:
            ntlog("Commit failed for unknown reasons", level=logging.ERROR)
        self._mode_restore()
        return result

    def config(self, cfg, commit=True):
        '''Take single line or multiline set config statements
        enter configuration mode, apply the configuration, and
        commit. Finally, it goes back to original mode. If commit
        is False, it skips commit and stay in config mode'''
        result = True
        mode_old = self._curr_mode
        result &= self.mode("config")
        for config in cfg.split("\n"):
            self._cmd_single(config)
        if commit:
            result &= self.commit()
            result &= self.mode(mode_old)
        return result

    def set_password(self, user, password=None, usrclass=None):
        '''
        For Junos devices, this sets a password in plain text for user
        '''
        mode = self._curr_mode
        self.mode("config")
        cfg = "login user %s " % user
        if user == "root":
            cfg = "root-"
        cfg = "set system " + cfg + "authentication plain-text-password"
        if usrclass is not None and user != "root":
            self.sendline("set system login user %s class %s" % (user, usrclass))
        result = True
        timeout = 10
        if password is None:
            if user == 'root':
                password = ntini['ROOTPW']
            else:
                password = ntini['PASSWORD']
        self.h.sendline('') # workaround the issue sometimes, hung at password
        try:
            self.h.sendline(cfg)
            #pattern = ['password:', 'error', PROMPT, pexpect.EOF, pexpect.TIMEOUT]
            #while True :
            #    idx = self.h.expect_exact(pattern, timeout=timeout)
            #    if idx == 0:
            #        self.h.sendline(password)
            #    elif idx == 1:
            #        result = False
            #        break
            #    elif idx == 2 or idx == 3:
            #        break
            #    elif idx == 4:
            #        ntlog(str(self.h))
            #        if re.search('password:', self.h.before):
            #            self.h.sendline(password)
            #        else:
            #            result = False
            #            break
            self.h.expect_exact('password:')
            self.h.sendline(password)
            self.h.expect_exact('password:')
            self.h.sendline(password)
            self.h.expect(PROMPT)
            result &= self.commit()
        except:
            result = False
        if not result :
            ntlog(str(self.h))
            ntlog("Password config failed with %s" % sys.exc_info()[0], level=logging.ERROR)
        self.mode(mode)
        return result

    def upload(self, local, remote, timeout=600):
        '''
        Upload a file from local to remote using xfer_proto
        '''
        return self._xfer(local, remote, oper="upload", timeout=timeout)

    def download(self, local, remote, timeout = 600):
        '''
        Download a file from remote to local using xfer_proto
        '''
        return self._xfer(local, remote, oper="download", timeout=timeout)
        
    def _xfer(self, local, remote, oper, timeout):
        result = False
        if self.xfer_proto == "scp":
            remote=self.user + '@' + self.host + ':' + remote
        else:
            ntlog("Only SCP is supported now, stay tuned for ftp", level=logging.ERROR)
            return result
        if oper == "download":
            src = remote
            dst = local
        elif oper == "upload":
            src = local
            dst = remote
        else:
            ntlog("unsupported file transfer operation " + str(oper), level=logging.ERROR)
            return result
        cmd = "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
        cmd += " -P " + str(self.port)
        if self.ssh_key is not None:
            cmd += " -i " + self.ssh_key
        cmd += " " + src + " " + dst
        msg = ''
        try:
            xfer = pexpect.spawn(cmd)
            match_pattern = ["assword:", '100%', pexpect.EOF]
            while True:
                i = xfer.expect(match_pattern, timeout = timeout)
                if i == 0:
                    xfer.sendline(self.passwd)
                elif i == 1:
                    pass
                    result = True
                elif i == 2:
                    break
        except Exception as e:
            msg = str(e)
            result = False
        if result:
            ntlog("SCP %s succeeded" % cmd)
        else :
            ntlog(("SCP %s failed" % cmd) + msg, level=logging.ERROR)
        return result

    def set_hostname(self, hostname):
        '''Set hostname, support both Ubuntu and Junos'''
        cmd = ''
        if self.os == "linux":
            cmd += "echo '%s' | sudo tee /etc/hostname > /dev/null" % hostname
            cmd += "\necho '127.0.1.1 %s'" % hostname + \
                " | sudo tee --append /etc/hosts > /dev/null"
            cmd += "\nsudo hostname %s" % hostname
            self.cmd(cmd=cmd, timeout=600)
            return True
        elif self.os == "junos":
            self.config("set system host-name %s" % hostname)
            return True
        else :
            ntlog("Changing hostname in OS %s is not " % hostname +
                "currently supported! Aborting...", logging.WARNING)
            return False

    def chk_pic(self, fpc=0, pic=0, timeout=0, retries=1):
        """check a single PIC at FPC/PIC slot number"""
        cmd = "show chassis pic fpc-slot %d pic-slot %d" % (fpc, pic)
        self.mode("cli")
        attempt = 1
        result = False
        while(attempt <= retries and not result) :
            sleep(timeout)
            root=ET.fromstring(self.cmd(cmd=cmd, xml="True"))
            if root.find(".//output") is not None:
                ntlog("PIC is not ready yet " + root.find(".//output").text)
            else:
                state = root.find(".//pic-detail[slot='" + str(fpc) +
                    "'][pic-slot='" + str(pic) + "']/state").text
                ntlog("PIC state is " + state)
                if state == "Online":
                    result = True
            attempt += 1

        return result

    def install_licenses(self, licenses):
        '''Upload and install licenses for Junos devices
        arguments licenses is a list of license file path'''
        result = True
        for lic in licenses:
            src = lic
            filename = src.split("/")[-1]
            dst = "/var/tmp/" + filename
            if self.upload(src, dst):
                ntlog("License %s uploaded" % filename)
            else:
                ntlog("License %s upload failed" % filename, level=logging.ERROR)
                result = False
            output = self.cli("request system license add " + dst)
            if re.search("no error", output, re.IGNORECASE):
                ntlog("License %s applied" % filename)
            else :
                result = False
                ntlog("License %s failed to apply" % filename)
        return result

    def set_snmp(self, comm_ro="public", comm_rw="private"):
        cmd = "set snmp community " + comm_ro + " authorization read-only"
        if comm_rw is not None:
            cmd += "\nset snmp community " + comm_rw + " authorization read-write"
        return self.config(cmd)

    def get_snmp(self, mib, comm="public"):
        '''Get a mib value, it takes either OID or MIB String'''
        result = False
        #try:
        #    snmpapi = importlib.import_module(pysnmp.hlapi)
        #except:
        #    ntlog("failed to import pysnmp.hlapi". logging.ERROR)
        #    return result
        #m = re.search(r'(\.\d+)+', mib)
        #if m:
        #    obj = snmpapi.ObjectType(snmpapi.ObjectIdentity(mib))
        #else:
        #    obj = snmpapi.ObjectType(snmpapi.ObjectIdentity('SNMPv2-MIB', 
        #        mib, 0))
        #errorIndication, errorStatus, errorIndex, varBinds = snmppi.next(
        #    snmpapi.getCmd(SnmpEngine(),
        #           snmpapi.CommunityData(comm, mpModel=0),
        #           snmpapi.UdpTransportTarget((self.host, 161)),
        #           snmpapi.ContextData(),
        #           snmpapi.ObjectType(obj))
        #)
        #if errorIndication:
        #    ntlog(errorIndication)
        #elif errorStatus:
        #    ntlog('%s at %s' % (errorStatus.prettyPrint(),
        #        errorIndex and varBinds[int(errorIndex) -1][0] or '?'),
        #        logging.ERROR)
        #else:
        #    result = {}
        #    for varBind in varBinds:
        #        pp.pprint(varBind)
        m = re.search(r'(\.\d+)+', mib)
        if m:
            obj = ObjectIdentity(mib)
        else:
            obj = ObjectIdentity('SNMPv2-MIB', mib, 0)
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                CommunityData(comm, mpModel=0),
                UdpTransportTarget((self.host, 161)),
                ContextData(),
                ObjectType(obj))
            )
        if errorIndication:
            ntlog(errorIndication)
        elif errorStatus:
            ntlog('%s at %s' % (errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) -1][0] or '?'),
                logging.ERROR)
        else:
            result = {}
            for varBind in varBinds:
                result = [x.prettyPrint() for x in varBind]
        return result[1]


def get_event(evt_name):
    events = {}
    events['restartRpd'] = {
        'desc':     "Restart RPD Once",
        'cmds':     [
            {0 :  [{'cmd': "restart routing", 'mode': "cli"},]}
            ],
        'check':    [
            {
                'rid':      0,
                'desc':     "router ID",
                'mode':     "cli",
                'cmd':      "show route summary",
                'xpath':    '//router-id',
                'match':    'exact',
            },
            ],
        'loss':     True,
        'interval': 5,
        'timeout':  300,
    }
    return events[evt_name]

def _init_kpi():
    kpis = {
        'bgpEvpnRouteCount':    {
            'tag'   :   "evpn",
            'desc'  :   "BGP EVPN route count",
            'mode'  :   "cli", #default
            'cmd'   :   "show route summary table bgp.evpn.0",
            'xpath' :   '//route-table[table-name="bgp.evpn.0"]/protocols/' + \
                'active-route-count',
            'match' :   'exact', # default, optional
        },
        'evpnMacTableCount':    {
            'tag'   :   "evpn,mactable",
            'desc'  :   "EVPN Mac Table Count",
            'cmd'   :   "show evpn mac-table count",
            'xpath' :   '//l2ald-rtb-learn-vlan-mac-count' + \
                '/l2ald-rtb-learn-vlan-mac-count-entry/mac-count',
        },
        'ipsecSecurityAssociation': {
            'tag'   :   "ipsec",
            'desc'  :   'IPSec Security Association',
            'cmd'   :   "show services ipsec-vpn ipsec security-associations",
            'xpath' :   "//sa-tunnel-information",
        },
        'routerId': {
            'tag'   :   'test',
            'desc'  :   'Test to retrieve a single value',
            'cmd'   :   "show route summary",
            'xpath' :   "//router-id",
        }
    }
    return kpis

def get_kpi_def(tag=[], name=[]):
    '''tag can be used to retrieve a collection of KPIs in same category,
    or if a list of KPI names can be used.
    return a dictionary of KPIs'''
    KPI = _init_kpi()
    if len(tag) == 0 and len(name) == 0:
        ntlog("either tag or name has to be provided", logging.ERROR)
    kpis = {}
    for kpi in name:
        if kpi not in KPI:
            ntlog("KPI %s does not exist, skipping...", logging.WARNING)
            continue
        kpis[kpi] = KPI[kpi]
    if len(tag) == 0:
        return kpis
    for kpi in KPI:
        tags = KPI[kpi].tag.split(",")
        if len(set(tag).intersection(tags)) > 0:
            kpis[kpi] = KPI[kpi]
    return kpis

def def_kpi_set(names=None):
    '''This is user defined routine to associate set of kpis to each device
    it needs more work to be flexible when not only DUT needs to be monitored
    Returns a list, with element 0 is a list of kpis for r0
    '''
    kpi_names = ['ipsecSecurityAssociation']
    return [get_kpi(name=kpi_names)]

def get_kpi_single(rh, kpi):
    '''expect the actual KPI definition being passed, without the KPI Key'''
    results = []
    if 'cmd' not in kpi:
        kpi_single = {}
        for key in kpi:
            kpi_single = kpi[key]
            break
        kpi = kpi_single
    if "mode" not in kpi or kpi['mode'] == "cli":
        if "regexp" in kpi:
            reg = []
            if type(kpi['regexp']) is list:
                reg = kpi['regexp']
            else:
                reg = [kpi['regexp']]
            resp = rh.cli(kpi['cmd'])
            for regex in reg:
                m = re.search(regex, resp)
                if m:
                    results.append(m.group(0))
                else:
                    ntlog("cli match: regexp %s failed to match response\n%s" \
                        % (regex, resp), logging.WARNING)
        if 'xpath' in kpi:
            xps = []
            if type(kpi['xpath']) is list:
                xps = kpi['xpath']
            else:
                xps = [kpi['xpath']]
            resp = rh.cmd(cmd=kpi['cmd'], mode='cli', xml='xpath')
            for xpath in xps:
                if xpath.startswith('//'):
                    xpath = "." + xpath
                leaf = resp.find(xpath)
                if leaf is not None:
                    results.append(leaf.text)
    else:
        ntlog("only cli command supported for this release", logging.WARNING)
    return results

def get_kpi_snapshot(rh, kpi_set):
    '''Get snapshot with kip_set and router handles'''
    kpi_ss = {} # kpi snapshot for this device
    for rid in kpi_set:
        kpi_ss[rid] = {} 
        for kpi_key in kpi_set[rid]:
            kpi_ss[rid][kpi_key] = get_kpi_single(rh[rid], 
                get_kpi_def(name=kpi_key))
    return kpi_ss

def compare_kpi_single(base, curr, kpi):
    key, k = kpi.items()[0]
    match = 'exact'
    percent = 1
    if 'match' in k or k['match'] == 'exact' :
        match = 'exact'
    elif k['match'] == 'percent':
        match = 'percent'
        if 'percent' in k:
            percent = k['percent']
    else:
        ntlog("match tpe %s not supported, default to exact" % k['match'],
            logging.WARNING)
    result = True
    for idx in range(len(base)):
        if match == 'exact':
            result &= base[idx] == curr[idx]
        elif match == 'percent':
            diff = abs(base[idx] - curr[idx])
            result &= (diff < 5) or (diff*1.0/base[idx]) < (percent / 100.0)
    return result 

def compare_kpi(base, curr, kpi):
    result = True
    for rid in base:
        for kpi_key in base[rid]:
            kbase = base[rid][kpi_key]
            kcurr = curr[rid][kpi_key]
            kpi_single = get_kpi_def(name=[kpi_key])
            result &= compare_kpi_single(base, curr, kpi_single)
    return rsult


def evt_precheck(event, devices):
    """Precheck testbed in steady state
    return a dictionary, where

        - status: True or False
        - baseline: dictionary of stats captured for comparison

    """
    if "mtd_steady" in event and hasattr(event['mtd_steady'], '__call__'):
        result = event['mtd_steady'](event, devices)
    else:
        result = get_baseline(event, devices)
    return result

def chk_event(self, event, devices, params=None):
    """event is a dictionary for the desirable event based on 
        a set of predefined event templates
    devices are handles of devices, it has 
        devices['r']: a list of router instances
        devices['h']: a list of host instances
        devices['t']: a list of tester instances

    event has the following key/value pairs
    
        name: a short name for the event, also the key to predefined
        events

        dut: integer. index for router

        mtd_steady : a method to bringup steady state before, during
        and/or after the event. In case of traffic forwarding, make
        sure zero loss during stead state, then starts traffic and
        begin event. After event converges, stop traffic and measure
        traffic loss as a result of the event. For some events, zero
        loss is expected throughput the event. For others, some traffic
        loss is expected, then make sure the loss is within expectation
        And finally, restart traffic measurement again and ensure
        the steady state can be reached with 0 traffic loss.

        template: a dictionary that defines a custom event if not already
        present in library, or any custom update required

    params is optional for misellaneous environment
    
    the event is declared success if impact is within the expected range,
        and steady state is reached after the event. Not used now
    """
    if 'template' in event:
        evt = event['template']
    else:
        evt = get_event(name=event['name'])
    r_before = evt_precheck(evt, devices)
    if r_before['status'] is False :
        ntlog("Baseline precheck failed, abort...")
        return False
    r_event = evt_start(evt, devices)
    r_after = evt_postcheck(evt, devices)
    return evt_cmp_results(evt, result=[r_before, r_event, r_after])

class Receiver(threading.Thread):
    '''Simple TCP/UDP server as a receiver for network traffic'''
    def __init__(self, ip, port, sock, regex=None, to=900, q=None):
        if sock != socket.SOCK_DGRAM:
            ntlog("Only UDP supported for now...", logging.ERROR)
            return None
        threading.Thread.__init__(self)
        self.r = socket.socket(socket.AF_INET, sock)
        self.match = False
        self.regex = regex
        self.to = to
        self.q = q
        self.r.bind((ip, port))

    def run(self):
        '''start the receiver'''
        data = ''
        ts = time.time()
        timeout = False
        match = False
        while not match and not timeout:
            data, addr = self.r.recvfrom(4096)
            match = re.search(self.regex, data)
            if match:
                self.match = True
                self.q.put(data)
                #ntlog("log received: %s" % data)
            timeout = time.time() - ts > self.to
        
if __name__ == "__main__" :
    pass
