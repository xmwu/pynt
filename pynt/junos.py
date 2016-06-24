'''Junos Common Library'''
from nt import *
import socket, time
import threading, Queue

class junos(NT):
    '''Junos router'''
    def __init__(self, host, user=None, password=None, rootpw=None, ssh_key=None):
        if user is None:
            user = ntini['USER']
        if password is None:
            password = ntini['PASSWORD']
        if rootpw is None:
            rootpw = ntini['ROOTPW']
        super(junos, self).__init__(
            host=host, 
            user=user,
            password=password,
            conn_proto = "ssh",
            os = "junos",
            ssh_key = ssh_key,)

    def chk_syslog_host(self, port=49999):
        grp = "syslog_" + str(port)
        ip = get_interface_ip("eth0")
        cfg_syslog="set groups " + grp + " system syslog host " + ip + \
             " port " + str(port) + " any any"
        result = False
        cfg_syslog += "\nset apply-groups " + grp
        self.config(cfg_syslog)
        random_str = "Test Message at " + str(time.time()) + " END"
        q = Queue.Queue()
        logsvr = Receiver(ip, port, socket.SOCK_DGRAM, regex=random_str, q=q)
        logsvr.start()
        self.mode("shell")
        self.cmd("logger \"" + random_str + "\"")
        self.mode("cli")
        if not q.empty():
            ntlog("logger command is " + random_str)
            ntlog("actual syslog received is " + q.get())
            result = True
        else:
            ntlog("pre generated log not received", logging.ERROR)
        logsvr.join()
        self.config("delete apply-groups " + grp + "\ndelete groups " + grp)
        return result

    def chk_snmp_trap(self, port=49998):
        grp = "trap" + str(port)
        ip = get_interface_ip("eth0")
        cfg_syslog="set groups " + grp + " snmp trap-group pynt " + \
            "destination-port " + str(port) + " targets " + ip
        result = False
        cfg_syslog += "\nset apply-groups " + grp
        self.config(cfg_syslog)
        expected = "ge-0/0/0";
        self.mode("shell")
        if not self.su():
            ntlog("Unable to su -")
            return False
        regex = re.escape(expected)
        q = Queue.Queue()
        logsvr = Receiver(ip, port, socket.SOCK_DGRAM, regex=regex, q=q)
        logsvr.start()
        self.cmd("ifconfig " + expected + " down")
        self.cmd("ifconfig " + expected + " up")
        self.sendline("exit")
        self.mode("cli")
        if not q.empty():
            ntlog("trap received for " + expected)
            result = True
        else:
            ntlog("SNMP Trap not received", logging.ERROR)
        logsvr.join()
        self.config("delete apply-groups " + grp + "\ndelete groups " + grp)
        return result

        



if __name__ == "__main__":
    pass
