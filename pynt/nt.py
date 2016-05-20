'''This class extends pexpect.spawn to simulate device handles and 
related operation methods
TODO - exception handling
'''
from __future__ import print_function
import time,datetime
import os,sys,re
import getopt,pexpect
import socket, struct
import binascii,logging

try:
    import pexpect.pxssh
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
PYNT_LOGFILE = os.environ.get('PYNT_LOGFILE', 'nt.log')
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

def get_ini():
    ini_values = {
        'USER':         'pynt',
        'PASSWORD':     'PyNT123',
        'ROOTPW':       'PyNt!2#',
    }
    ini = []
    for key, value in ini_values.iteritems():
        ini[key] = os.environ.get('PYNT_' + key, value)
    return ini

ini = get_ini()

def ntlogger():
    logLevel = logging.DEBUG
    nlog = logging.getLogger('pynt')
    nlog.setLevel(logLevel)
    #nlog.setLevel(logLevel)
    fh = logging.FileHandler(PYNT_LOGFILE)
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
        * *rootpw: default root password is PyNt!2# or ENV PYNT_ROOTPW
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
        self.user = kargs.pop('user', ini['USER'])     #SECURITY
        self.passwd = kargs.pop('password', ini['PASSWORD']) # SECURITY
        self.rootpw = kargs.pop('rootpw', ini['ROOTPW'])   # SECURITY
        self.os = kargs.pop('os', 'junos').lower()       # OS
        self.tag = kargs.pop('tag', "R")                 # alias like r1
        self.conn_proto = kargs.pop('conn_proto', 'ssh') # ssh/telnet
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
            self.h = pexpect.pxssh.pxssh(
                options={"StrictHostKeyChecking": "no", 
                "UserKnownHostsFile": "/dev/null"})
            #self.h.SSH_OPTS += " -o StrictHostKeyChecking=no"
            #self.h.SSH_OPTS += " -o UserKnownHostsFile=/dev/null"
            self.h.logfile_read = sys.stdout #debug
            self.h.PROMPT = NT.PROMPT
            self.h.login(self.host, self.user, self.passwd, 
                ssh_key=self.ssh_key,
                auto_prompt_reset=self.auto_prompt_reset,
                original_prompt = NT.PROMPT,
            )
            if self.os == 'junos':
                self.cmd("cli")
                self._old_mode = self._curr_mode
                self._curr_mode = "cli"
        else :
            ntlog("the conn_proto is not supported\n")

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
        return self.os

    def chk_hostup(self, port, interval=5, timeout=30, family=socket.AF_INET):
        s = socket.socket(family, socket.SOCK_STREAM)
        ts_start = time.time()
        hostup = False
        while time.time() - ts_start <= timeout:
            try:
                s.connect(self.host, port)
                ntlog("Host %s is reachable at port %d" %(self.host, port))
                hostup = True
                break
            except socket.error as e:
                ntlog("Host %s is not reachable at port %d." % (self.host,
                    port))
            sleep(interval)
        if not hostup:
            ntlog("Host %s is not reachable before %d seconds timeout" % \
                (self.host, timeout))
        return hostup
        
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
            pass
        if mode == "config":
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

    def cmd(self, cmd, mode=None, timeout=CMD_TIMEOUT) :
        '''
        Execute a single command if a string is passed. If a list is provided
        via cmd arguments, it executes all commands one by one
        '''
        mode_restore = 0
        output = []
        if mode is not None:
            self.mode(mode)
            mode_restore = 1
        if type(cmd) is list:
            for onecmd in cmd:
                output.append(self._cmd_single(onecmd, timeout))
        else:
            output = self._cmd_single(cmd, timeout)
        if mode_restore :
            self._mode_restore()
        return output

    def _cmd_single(self, cmd, timeout=CMD_TIMEOUT):
        if self.os == "junos" and self._curr_mode == "cli" \
            and not cmd.endswith("no-more"):
            cmd += " | no-more"
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
        return "\n".join(self.h.before.split("\n")[1:-1])

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
            self.h.sendline(cmd)
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

    def config(self, cfg):
        '''Take single line or multiline set config statements
        enter configuration mode, apply the configuration, and
        commit. Finally, it goes back to original mode'''
        result = True
        result &= self.mode("config")
        for config in cfg.split("\n"):
            self._cmd_single(config)
        result &= self.commit()
        result &= self._mode_restore()
        return result

    def set_password(self, user, password=None):
        '''
        For Junos devices, this sets a password in plain text for user
        '''
        mode = self._curr_mode
        self.mode("config")
        cfg = "login user %s " % user
        if user == "root":
            cfg = "root-"
        cfg = "set system " + cfg + "authentication plain-text-password"
        result = True
        if password is None:
            if user == 'root':
                password = ini['ROOTPW']
            else:
                password = ini['PASSWORD']
        try:
            self.h.sendline(cfg)
            pattern = [PROMPT, 'error', 'password:']
            while True :
                idx = self.h.expect(pattern, timeout=self.timeout)
                if idx == 0:
                    break
                elif idx == 1:
                    result = False
                    break
                elif idx == 2:
                    self.h.sendline(password)
            result &= self.commit()
        except:
            result = False
        if not result :
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

if __name__ == "__main__" :
    pass