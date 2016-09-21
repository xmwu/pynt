import sys,os,getopt
from nt import *
import awsec2
import importlib, json, datetime

json.JSONEncoder.default = lambda self,obj: (obj.isoformat() if isinstance(obj, datetime.datetime) else None)

#BEGIN Initialization
vmx_subnets = []
# these are important and should be specified by user
ami_ubuntu = ntini['AWS_AMI_LNX']
ami_vmx = ntini['AWS_AMI_VMX']
ec2_key_name = ntini['AWS_KEYNAME']
ec2_key_file = ntini['AWS_KEYFILE']

# the following are just default values that should be passed
# by calling method
vmx_inst_type = ntini['AWS_VMX_TYPE']
lnx_inst_type = ntini['AWS_LNX_TYPE']
vmx_region_name = ntini['AWS_REGION']
AWS_ADDR_LOW = 4
AWS_VPC_NAME = ntini['AWS_VPC_NAME']
AWS_VPC_CIDR_BLOCK = "192.168.128.0/17"
AWS_VPC_SUBNET_MASK = 24
AWS_VPC_SUBNET_CNT = 4
AWS_VPC_ENI_PER_SUBNET = 4

#END Initialization
#aws_eips = ['52.8.71.213', '52.8.143.131', '52.8.192.197', '52.9.2.199',
#    '52.9.150.32']
#aws_eips = [] # sorted EIPs for given account

class VmxAws(object):
    '''
    A collection of operations and testcases for VMX in AWS Environment
    '''

    def __init__(self, vpc=AWS_VPC_NAME, cidr=None,
        subnet_mask = AWS_VPC_SUBNET_MASK, subnet_cnt=AWS_VPC_SUBNET_CNT):
        '''
        VMX testing in AWS
        '''
        self.aec2 = awsec2.AwsEc2()
        if self.aec2.vpcid_by_name(vpc) is not None:
            self.evpc = awsec2.Ec2Vpc(aec2=self.aec2, name=vpc)
            self.cidr = self.evpc.cidr
            self.subnet_mask = self.evpc.subnet_mask
            self.subnet_cnt = len(self.evpc.nets)
        else:
            self.subnet_mask = int(subnet_mask)
            self.subnet_cnt = int(subnet_cnt)
            if cidr is None:
                self.cidr = AWS_VPC_CIDR_BLOCK
            else:
                self.cidr = str(cidr)
            self.evpc = awsec2.Ec2Vpc(aec2=self.aec2, name=vpc, cidr=self.cidr,
            subnet_mask=self.subnet_mask)
        self.subnet_cidr = get_subnets(base=self.cidr, mask=self.subnet_mask,
            num = self.subnet_cnt)
        self.placement = {}
        if ntini['AWS_PLACE_GROUP_NAME'] != '' :
            self.placement['GroupName'] = ntini['AWS_PLACE_GROUP_NAME']

    def vpc_cleanup(self):
        '''cleanup VPC and its associated resources'''
        self.evpc.cleanup()

    def vpc_create_subnet(self, subnet_cnt=AWS_VPC_SUBNET_CNT):
        self.evpc.add_subnets(subnet_cnt)

    def vpc_create_security_groups(self):
        self.evpc.set_security_groups_basic()

    def vpc_create_interface(self, eni_per_subnet=AWS_VPC_ENI_PER_SUBNET, 
        addr_low=AWS_ADDR_LOW):
        '''Create ENIs and assign private IP addresses'''
        subnet_cnt = self.evpc.get_subnet_count()
        sg_names = ['ext-pub', 'int-vpc']
        sgs = []
        for sg in sg_names:
            sgs.append(self.evpc.sgs[sg].group_id)
        for subnetidx in range(subnet_cnt):
            subnet_addr = self.subnet_cidr[subnetidx]
            for offset in range(addr_low, (addr_low + eni_per_subnet)):
                addr = ip_add(strip_mask(subnet_addr), offset)
                ips = [addr]
                if subnetidx == 0 :
                    ips.append(decimal2ip(ip2decimal(addr) + 
                        2**(32 - self.subnet_mask - 1)))
                self.evpc.add_if(ip=ips, sgs=sgs)

    def vpc_create_route_table(self, rtt_cnt=3):
        self.evpc.add_route_tables(rtt_cnt)

    def vpc_create_internet_gateway(self):
        '''Create a new Internet Gateway, if not existed yet. Set default route
        to Internet Gateway in main route table for the VPC'''
        self.evpc.get_internet_gateway()
        self.evpc.set_route_table_main_gw()
        
    def _launch_instance(self, inst_name, ami, key_name, inst_type, ips, 
        placement):
        #inst_params = {
        #    "vmx01": ["192.168.0.4", "192.168.1.4", "192.168.2.4"],
        #    #"vmx02": ["192.168.0.5", "192.168.2.5", "192.168.3.5"],
        #}
        vmx_enis = []
        sg_names = ['ext-pub', 'int-vpc']
        sgs = []
        for sg in sg_names:
            sgs.append(self.evpc.sgs[sg].group_id)
        for pip in ips :
            if not chk_ip(pip):
                if re.match('^\d+\.\d+$', pip):
                    parts = pip.split('.')
                    net = self.evpc.nets[int(parts[0])].cidr_block
                    pip = ip_add(strip_mask(net), int(parts[1]) + AWS_ADDR_LOW)
                else:
                    ntlog("Invalid interface IP address", level=logging.ERROR)
            if pip not in self.evpc.enis:
                eni = self.evpc.add_if(ip=pip, sgs=sgs)
            else:
                eni = self.evpc.enis[pip]
            vmx_enis.append(eni)
            ntlog("Private IP is " + pip)
        awsec2.Ec2Instance(evpc = self.evpc, 
            enis = vmx_enis, name = inst_name, placement = placement,
            inst_type = inst_type, key_name = key_name, ami_id = ami)

    def launch_instances(self, inst_params, ami=ami_vmx,
        key_name=ec2_key_name, inst_type=vmx_inst_type, ifcount = 3,
        placement = {}) :
        # launch vmx instances with inst_params as dictionary with keys
        # name, addr_start (+offset from addr_low), ami_id, inst_type, if_cnt
        if len(placement) == 0:
            placement = self.placement
        for inst_p in inst_params :
            if inst_p['iname'] in self.evpc.ec2instances:
                ntlog("VMX Instance already exists, setup aborted.")
                return False
            name = inst_p['iname']
            _ifcount = ifcount
            if "ifcount" in inst_p :
                _ifcount = inst_p["ifcount"]
            _inst_type = inst_type
            if "itype" in inst_p :
                _inst_type = inst_p["itype"]
            _ami = ami
            if "ami" in inst_p :
                _ami = inst_p["ami"]
            _ips = []
            if "offset" in inst_p :
                for ifid in range(_ifcount):
                    _ips.append(str(ifid) + '.' + str(inst_p['offset']))
            if "ips" in inst_p :
                _ips = inst_p["ips"]
            self._launch_instance(inst_name=name, key_name=key_name, 
                inst_type=_inst_type, ami=_ami, ips=_ips, placement=placement)

    def _launch_two_vmx(self):
        iparams = [
            {'iname': 'vmx01', 'offset': 0, 'itype': 'm4.xlarge'},
            {'iname': 'vmx02', 'offset': 3, 'itype': 'm4.2xlarge'},
            ]
        ami= 'ami-05daa465'
        self.launch_instances(inst_params=iparams, ami=ami)


    def _launch_vmx_instance(self, ami, inst_name, inst_type, key_name, enis) :
        #if inst_name == "vmx01" and len(enis) == 0:
        #    for ifid in range(vmx_intf_cnt+1):
        #        addr = ip_add(strip_mask(self.subnet_cidr[ifid]), AWS_ADDR_LOW)
        #        enis.append(addr)
        awsec2.Ec2Instance(evpc=self.evpc, enis=inst_enis, name=inst_name,
            inst_type=inst_type, key_name=key_name, ami_id=ami)
        self.aec2.associate_eip(evpc=self.evpc, 
            pub=self.aec2.pubips[eip_id], pvt=enis[0])


    def eip_associate(self, pub_ip_idx, pvt_ip):
        pub_ip = self.aec2.pubips[pub_ip_idx]
        self.aec2.associate_eip(evpc=self.evpc, pub = pub_ip, pvt = pvt_ip)
        ntlog("Now Private Address %s is mapped to Public Address %s" % \
            (pvt_ip, pub_ip))

    def start_instance(self, inst_name, wait=False):
        if type(inst_name) is not list:
            inst_name = [inst_name]
        for iname in inst_name:
            self.evpc.ec2instances[iname].start()

        
    def stop_instance(self, inst_name):
        if type(inst_name) is not list:
            inst_name = [inst_name]
        for iname in inst_name:
            self.evpc.ec2instances[iname].stop()
        
    def terminate_instance(self, inst_name):
        '''Terminate instance'''
        if type(inst_name) is not list:
            inst_name = [inst_name]
        for iname in inst_name:
            self.evpc.ec2instances[iname].terminate()


    def install_iperf3(self, inst_name, key=ec2_key_file):
        if type(inst_name) is not list:
            inst_name = [inst_name]
        for iname in inst_name:
            self.evpc.ec2instances[iname].install_iperf3(key=key)

    def install_ixgbevf(self, inst_name, key=ec2_key_file):
        if type(inst_name) is not list:
            inst_name = [inst_name]
        for iname in inst_name:
            self.evpc.ec2instances[iname].install_ixgbevf(key=key)

    def throughput_with_iperf3(self, host1, host2, gw=[0, 0], ifidx=[1, 2]):
        self.evpc.get_throughput(host1, host2, ec2_key_file, gw, ifidx)

    def perf_report(self, host1, host2, key=ec2_key_file,
        gw_offset=[0, 0], ifidx=[1, 2]):
        '''
        Taking existing topology and report iperf3 thruput

            host1 <-> vmx1 <-> vmx2 <-> host2
                       <- IPSEC ->

        By varying the following
            
            * Direct - apply-groups direct. without IPSec
            * IPSec Tunnel - apply-groups ipsec with enc/auth combo
                * 3des-cbc          hmac-sha1-96
                * aes-256-cbc       hmac-sha1-96
                * aes-128-cbc       hmac-sha1-96
                * aes-256-gcm       None
                * aes-128-gcm       None
        
        For each of 6 combinations above, change TCP MSS as follows
            
            * 1448 : max/default MSS assuming 52 bytes IPSec overhead
            * 1408 : 1408 + 40 IP/TCP HDR + 52 IPSec HDR = 1500
            * 1300 : 
            * 1000 :
            *  500 :
            *  128 : Expect low throughput, but high pps relatively

        TODO:
            UDP performance number
            PPS reading from VMX since iperf3 doesn't report this
        '''
        results = [] # list of dict w/ enc, auth, mss, bps
        ipsec = [
            #['3des-cbc',        'hmac-sha1-96'],
            ['aes-256-cbc',     'hmac-sha1-96'],
            #['aes-256-gcm',     None],
            #['aes-128-cbc',     'hmac-sha1-96'],
            ['aes-128-gcm',     None],
            ]
        mss = [1448, 1400]
        #mss = [1448, 1400, 1300, 1000, 500, 128]
        # mss = [1448, 1408, 1300, 1000, 500, 128]
        pub_add = []
        pvt0_add = []
        pvt_add = []
        pvt_gw = []
        hosts = [host1, host2]
        vmx=[]
        host_type = []
        for idx in range(2):
            inst = self.evpc.ec2instances[hosts[idx]]
            host_type.append(inst.instance.instance_type)
            ifid = ifidx[idx]
            if inst.instance.public_ip_address is not None:
                pub_add.append(inst.instance.public_ip_address)
            else:
                pub_add.append(inst.instance.private_ip_address)
            pvt0_add.append(inst.instance.private_ip_address)
            inst.cfg_eth(key, ifid)
            pvt_add.append(inst.pips[ifid])
            gw = ip_add(strip_mask(inst.enis[ifid].subnet.cidr_block),
                 AWS_ADDR_LOW + gw_offset[idx])
            pvt_gw.append(gw)
            vmx_name = "vmx%02d" % gw_offset[idx]
            vmx.append(Vmx(self.evpc.ec2instances[vmx_name]))
        iperf = awsec2.IPerf(server=pub_add[0], client=pub_add[1], 
                user="ubuntu", key=key)
        iperf.connect()
        iperf.start_server()
        #iperf.get_bandwidth(udp=True)
        results = []
        for grp in ["no_vmx", "direct"]:
            ntlog("Testing Throughput with %s connection" % grp)
            if grp == "no_vmx":
                iperf.config(saddr=pvt0_add[0], caddr=pvt0_add[1], duration=10)
            else :
                cfg = "delete apply-groups direct\n"
                cfg += "delete apply-groups ipsec\n"
                cfg += "set apply-groups " + grp
                for v in vmx:
                    v.config(cfg)
                iperf.config(saddr=pvt_add[0], caddr=pvt_add[1],
                    sgateway=pvt_gw[0], cgateway=pvt_gw[1])
            for tcp_mss in mss:
                result = iperf.get_bandwidth(mss=tcp_mss)
                for record in result:
                    record['dut_type'] = grp
                    record['enc_alg'] = grp
                    record['auth_alg'] = 'noauth'
                    record['host_type'] = host_type[0]
                    record['vmx_type'] = vmx[0].inst_type
                    results.append(record)
        # ipsec here)
        for v in vmx:
            cfg = "delete apply-groups direct\n"
            cfg += "set apply-groups ipsec\n"
            v.config(cfg, commit=False)

        for enc, authen in ipsec:
            cfg_path = "groups ipsec services ipsec-vpn ipsec proposal" + \
                " ipsec_proposal_1 "
            cfg = "set " + cfg_path + "encryption-algorithm " + enc + "\n"
            if authen is None:
                cfg += "delete " + cfg_path + " authentication-algorithm\n"
            else:
                cfg += "set " + cfg_path + " authentication-algorithm " + \
                    authen + "\n"
            for v in vmx:
                v.config(cfg)
                v.cli("clear services ipsec-vpn ipsec security-associations")
            for tcp_mss in mss:
                result = iperf.get_bandwidth(mss=tcp_mss)
                for rec in result:
                    rec['dut_type'] = 'ipsec'
                    rec['enc_alg'] = enc
                    rec['auth_alg'] = authen
                    rec['host_type'] = host_type[0]
                    rec['vmx_type'] = vmx[0].inst_type
                    results.append(rec)
        ntlog(pp.pprint(results))
        return results



    def setup_vmx(self, ami, inst_name="vmx01", enis=[],
        inst_type=vmx_inst_type, key_name=ec2_key_name, 
        vmx_intf_cnt=3, eip_id=0, addr_low=AWS_ADDR_LOW):
        if inst_name in self.evpc.ec2instances:
            ntlog("VMX Instance already exists, setup aborted.")
            return False
        if inst_name == "vmx01" and len(enis) == 0:
            for ifid in range(vmx_intf_cnt+1):
                addr = ip_add(strip_mask(self.subnet_cidr[ifid]), AWS_ADDR_LOW)
                enis.append(addr)
        inst_enis = []
        for pip in enis:
            inst_enis.append(self.evpc.enis[pip])
        awsec2.Ec2Instance(evpc=self.evpc, enis=inst_enis, name=inst_name,
            inst_type=inst_type, key_name=key_name, ami_id=ami)
        self.aec2.associate_eip(evpc=self.evpc, 
            pub=self.aec2.pubips[eip_id], pvt=enis[0])


    def setup_all(self, ami_vmx, subnet_cnt=4, addr_low=AWS_ADDR_LOW, 
        eni_per_subnet=24, rtt_cnt=3, vmx_intf_cnt=2, 
        inst_type_vmx=vmx_inst_type, inst_type_lnx=lnx_inst_type, 
        key_name=ec2_key_name, ami_lnx=ami_ubuntu):

        #self.vpc_cleanup()
        #self.vpc_create_subnet(subnet_cnt)
        #self.vpc_create_security_groups()
        #self.vpc_create_interface(eni_per_subnet=eni_per_subnet,
        #    addr_low = addr_low)
        #self.vpc_create_route_table(rtt_cnt = rtt_cnt)
        #self.vpc_create_internet_gateway()
        for name in ("lnx01", "lnx02") :
            evpc.ec2instances[name].install_iperf3(key=ec2_key_file)

    def cfg_iperf3_vmx(self, vmx_name="vmx01"):
        vmx = Vmx(self.evpc.ec2instances[vmx_name])
        vmx.cfg_interfaces()

    def get_console_output(self, inst_name):
        '''Get console output for debug purpose. 
        AWS allows read-only snapshot of console output from the instance
        interactive operations via console is not possible'''
        inst = self.evpc.ec2instances[inst_name]
        console = self.evpc.client.get_console_output(
            InstanceId = inst.instance.instance_id)
        output = "Console Output on " + str(console['Timestamp']) + "\n" + \
            console['Output']
        ntlog(output)
        
    def chk_sriov(self, inst_name):
        '''Check whether SR-IOV or Enhanced Networking is enabled'''
        inst = self.evpc.ec2instances[inst_name]
        status = "disabled"
        if inst.chk_sriov():
            status = "enabled"
        ntlog("SRIOV Net Support for instance %s is %s" % (inst_name, status))
        return status == "enabled"

    def enable_sriov(self, inst_name):
        if type(inst_name) is not list:
            inst_name = [inst_name]
        for iname in inst_name:
            inst = self.evpc.ec2instances[iname]
            inst.enable_sriov()

    def cfg_lnx_hosts(self, instances):
        for instance in instances:
            inst = str(instance)
            self.install_iperf3(inst)
            self.install_ixgbevf(inst)
            self.stop_instance(inst)
            self.enable_sriov(inst)
            self.start_instance(inst)

    def vmx_install_license(self, inst_name, licenses=None):
        vmx = Vmx(self.evpc.ec2instances[inst_name])
        lic = []
        if licenses is not None:
            lic = licenses.split(":")
        vmx.install_license(lic)

    def vfp_http_enable(self, name):
        vmx = Vmx(self.evpc.ec2instances[name])
        return vmx.set_riot_http()
        

    def vmx_basic_setup(self, names, rootpw=None, licenses=None):
        '''Basic setup for newly launched VMX, including

            * install licenses
            * setup root password
            * add non-Root user to superuser class
            * assign static IP addresses from ENI
            * stage configuration for direct and IPsec groups
            * enable http access to RIOT stats

        '''
        if type(names) is not list:
            names = [names]
        result = True
        for name in names:
            name = str(name)
            vmx = Vmx(self.evpc.ec2instances[name])
            if rootpw is None:
                rootpw = ntini['ROOTPW']
            result &= vmx.set_password("root", rootpw)
            result &= vmx.set_password(ntini['USER'], ntini['PASSWORD'],
                usrclass="super-user")
            if licenses is None and 'VMX_LIC' in ntini and \
                ntini['VMX_LIC'] is not None:
                licenses = ntini['VMX_LIC']
            if licenses is not None:
                lic = licenses.split(":")
                result &= vmx.install_license(lic)
            else:
                ntlog("License not specified, skipping lic installation")
            result &= vmx.cfg_interfaces()
            result &= vmx.cfg_ipsec_direct()
            result &= vmx.chk_pic(fpc=0, pic=0, timeout=15, retries=20) 
            result &= vmx.set_riot_http()
        return result

    def launch_lnx_instances(self, inst_params):
        itype_lnx = "m4.10xlarge"
        ifcount = 5
        lnx_instances = []
        for idx in [23, 24]:
            inst_param = {
                'iname':    "lnx%02d" % (idx),
                'itype':    itype_lnx,
                'ips':      []
            }
            for ifidx in range(ifcount):
                inst_param['ips'].append("%d.%d" % (ifidx, idx))
            lnx_instances.append(inst_param)
        self.launch_instances(inst_params = lnx_instances, ami=ami_ubuntu)

    def launch_ipsec_instances(self, inst_params=None, ipsecvmx=[0]):
        inst_pairs = [
            {"seq": [3, 4], "itype": "m4.xlarge"},
            {"seq": [5, 6], "itype": "m4.2xlarge"},
            {"seq": [7, 8], "itype": "m4.4xlarge"},
            {"seq": [9, 10], "itype": "m4.10xlarge"},
            {"seq": [11, 12], "itype": "c3.2xlarge"},
            {"seq": [13, 14], "itype": "c3.4xlarge"},
            {"seq": [15, 16], "itype": "c3.8xlarge"},
            {"seq": [17, 18], "itype": "c4.2xlarge"},
            {"seq": [19, 20], "itype": "c4.4xlarge"},
            {"seq": [21, 22], "itype": "c4.8xlarge"},
            {"seq": [25], "itype": "c4.8xlarge", "if_cnt": 8},
            ]
        vmx_instances = []
        for vmxid in ipsecvmx:
            vmx_instances.append(inst_pairs[vmxid])
        for vmx_inst in vmx_instances:
            inst_params = []
            for seqid in range(len(vmx_inst['seq'])): # only 1 or 2
                seq = vmx_inst["seq"][seqid]
                inst_param = {"iname": "vmx%02d" % seq}
                if "if_cnt" in vmx_inst and vmx_inst['if_cnt'] > 3:
                    inst_param["ips"] = []
                    for ifidx in range(vmx_inst['if_cnt']):
                        inst_param["ips"].append("%d.%d" % (ifidx, seq))
                else :
                    inst_param["ips"] = ["0.%d" % seq, 
                        "%d.%d" % (seqid + 1, seq), "3.%d" % seq]
                inst_param["itype"] = vmx_inst["itype"]
                inst_params.append(inst_param)
            self.launch_instances(inst_params = inst_params, ami = ami_vmx)

    def set_vpc_peering(self, vpcs):
        if len(vpcs) != 2:
            ntlog("Two VPC name required to setup VPC Peering, aborting",
                logging.ERROR)
            return False
        self.aec2.set_vpc_peering(vpcs[0], vpcs[1])

    def chk_lo0_fw(self, vmx_name, lnx_name):
        """verify lo0 filter function using vmx_name as DUT, and lnx_name
        as traffic generator"""
        vmx = Vmx(self.evpc.ec2instances[vmx_name])
        lnx = self.evpc.ec2instances[lnx_name]
        vmx.set_lo0_fw_simple()
        dip = lnx.instance.private_ip_address
        dport = 8000
        cmd = "sudo hping3 -p %d -2 --flood --rand-source " % dport + dip

    def chk_reachability(self, host, port, timeout=300, interval=15, prompt=None):
        """verify whether host is reached at TCP port witin timeout"""
        return chk_host_port(host=host, port=port, timeout=timeout, interval=interval, prompt=prompt)

class Vmx(NT):
    license_path = "../misc/aws"
    licenses = {"bw_20G":      "Lic20G.txt", 
                    "feat_premium":  "E418396532.lic",
    }
    license_bundle = ["bw_20G", "feat_premium"]

    def __init__(self, ec2inst, **kargs):
        self.ec2inst = ec2inst
        self.name = ec2inst.name
        self.intf_type = "ge"
        self.inst_type = self.ec2inst.instance.instance_type
        public = False
        self.vcpaddr = ec2inst.instance.private_ip_address
        if public : # check whether public ip is associated
            self.vcpaddr = ec2inst.instance.public_ip_address
        self.vfpaddr = None
        pips_fxp0 = ec2inst.enis[0].private_ip_addresses
        if len(pips_fxp0) > 1 :
            if public and "Association" in pips_fxp0[1]:
                self.vfpaddr = pips_fxp0[1]["Association"]["PublicIp"]
            else :
                self.vfpaddr = pips_fxp0[1]['PrivateIpAddress']
        super(Vmx, self).__init__(
            host = self.vcpaddr,
            user = kargs.pop('user', "root"),
            os = "junos",
            conn_proto ="ssh",
            ssh_key=kargs.pop('ssh_key', ec2_key_file),
            )
        self.vfp = None
        if self.vfpaddr is not None:
            self.vfp = NT(
                host = self.vfpaddr,
                user = 'root',
                password = 'root',
                os = "linux",
                )

        
    def cfg_interfaces(self):
        cfg = ""
        ifprefix = self.intf_type + "-0/0/"
        for ifid in range(0, len(self.ec2inst.enis)-1):
            cfg += "set interfaces %s%d unit 0 family inet"  % (ifprefix, ifid)
            cfg += " address %s/%s\n" % (self.ec2inst.pips[ifid+1], 
                get_mask(self.ec2inst.evpc.nets[ifid+1].cidr_block))
        cfg += "set system host-name " + self.name
        self.config(cfg)
        return True
        #self.commit()

    def cfg_ipsec_direct(self):
        subnet = [1, 2]
        ifid = 2 # 2nd junos intf, 3rd inst intf, and 4th evpc subnet
        evpc = self.ec2inst.evpc
        nets = []
        for netid in subnet:
            nets.append(self.ec2inst.evpc.nets[netid].cidr_block)
        local_ip = self.ec2inst.pips[ifid]
        local_ip_dec = ip2decimal(local_ip)
        ip_delta = 1
        net_delta = 1
        if local_ip_dec % 2 == 0 :
            ip_delta = -1 
            net_delta = 0
        remote_ip = decimal2ip(local_ip_dec + ip_delta)
        src_block = nets[1-net_delta]
        dst_block = nets[net_delta]
        config = """delete groups ipsec
delete groups direct        
set groups ipsec chassis fpc 0 pic 0 inline-services bandwidth 1g
set groups ipsec services service-set ips_ss1 next-hop-service inside-service-interface si-0/0/0.1
set groups ipsec services service-set ips_ss1 next-hop-service outside-service-interface si-0/0/0.2
set groups ipsec services service-set ips_ss1 ipsec-vpn-options local-gateway IPSEC_LOCAL_GATEWAY_IP
set groups ipsec services service-set ips_ss1 ipsec-vpn-options tunnel-mtu 9192
set groups ipsec services service-set ips_ss1 ipsec-vpn-rules vpn_rule_1
set groups ipsec services ipsec-vpn rule vpn_rule_1 term term11 from source-address IPSEC_SRC_ADDRESS_BLOCK
set groups ipsec services ipsec-vpn rule vpn_rule_1 term term11 from destination-address IPSEC_DST_ADDRESS_BLOCK
set groups ipsec services ipsec-vpn rule vpn_rule_1 term term11 then remote-gateway IPSEC_REMOTE_GATEWAY_IP
set groups ipsec services ipsec-vpn rule vpn_rule_1 term term11 then dynamic ike-policy ike_policy_1
set groups ipsec services ipsec-vpn rule vpn_rule_1 term term11 then dynamic ipsec-policy ipsec_policy_1
set groups ipsec services ipsec-vpn rule vpn_rule_1 term term11 then anti-replay-window-size 4096
set groups ipsec services ipsec-vpn rule vpn_rule_1 match-direction input
set groups ipsec services ipsec-vpn ipsec proposal ipsec_proposal_1 protocol esp
set groups ipsec services ipsec-vpn ipsec proposal ipsec_proposal_1 authentication-algorithm hmac-sha1-96
set groups ipsec services ipsec-vpn ipsec proposal ipsec_proposal_1 encryption-algorithm 3des-cbc
set groups ipsec services ipsec-vpn ipsec policy ipsec_policy_1 perfect-forward-secrecy keys group2
set groups ipsec services ipsec-vpn ipsec policy ipsec_policy_1 proposals ipsec_proposal_1
set groups ipsec services ipsec-vpn ike proposal ike_proposal_1 authentication-method pre-shared-keys
set groups ipsec services ipsec-vpn ike proposal ike_proposal_1 dh-group group1
set groups ipsec services ipsec-vpn ike policy ike_policy_1 version 2
set groups ipsec services ipsec-vpn ike policy ike_policy_1 proposals ike_proposal_1
set groups ipsec services ipsec-vpn ike policy ike_policy_1 pre-shared-key ascii-text "$9$PTF/uORlK8CtK8X7sYfTz3Ct0BIcre"
set groups ipsec services ipsec-vpn establish-tunnels immediately
set groups ipsec interfaces si-0/0/0 unit 0 family inet
set groups ipsec interfaces si-0/0/0 unit 0 family inet6
set groups ipsec interfaces si-0/0/0 unit 1 family inet
set groups ipsec interfaces si-0/0/0 unit 1 family inet6
set groups ipsec interfaces si-0/0/0 unit 1 service-domain inside
set groups ipsec interfaces si-0/0/0 unit 2 family inet
set groups ipsec interfaces si-0/0/0 unit 2 family inet6
set groups ipsec interfaces si-0/0/0 unit 2 service-domain outside
set groups ipsec routing-options static route IPSEC_DST_ADDRESS_BLOCK next-hop si-0/0/0.1
set groups direct routing-options static route IPSEC_DST_ADDRESS_BLOCK next-hop IPSEC_REMOTE_GATEWAY_IP"""        
        cfg_params = {
            "IPSEC_LOCAL_GATEWAY_IP":   local_ip,
            "IPSEC_REMOTE_GATEWAY_IP":  remote_ip,
            "IPSEC_SRC_ADDRESS_BLOCK":  src_block,
            "IPSEC_DST_ADDRESS_BLOCK":  dst_block,
        }
        for cfg_key in cfg_params:
            config = config.replace(cfg_key, cfg_params[cfg_key])
        return self.config(config)        

    def install_license(self, licenses=[]):
        lics = []
        if len(licenses) == 0:
            for lic_name in Vmx.license_bundle:
                lics.append("/".join([Vmx.license_path, Vmx.licenses[lic_name]]))
        else:
            lics = licenses
        return self.install_licenses(lics)

    def chk_netconf(self, cmd="show version"):
        self.config("set system services netconf ssh")
        try:
            j = importlib.import_module('jnpr.junos')
        except:
            ntlog("jnpr.junos module import failed.", logging.ERROR)
            return False
        dev = j.Device(host=self.host, user=self.user, 
            ssh_private_key_file=self.ssh_key)
        dev.open()
        resp_nc = "\n".join(dev.cli("show version", warning=False).split("\n")[1:])
        resp_cli = self.cmd("show version")
        #resp_nc = "\n".join(dev.cli("show version", warning=False).split("\n")[1:-1])
        #resp_cli = "\n".join(self.cmd("show version").split("\r\n")[:-1])

        if resp_nc == resp_cli :
            ntlog("Netconf Quick Check Passed")
            return True
        else :
            ntlog("Netconf quick check failed")
            return False
 
    def chk_riot_web(self):
        """Check web console stats can be properly downloaded"""

    def get_riot_stats(self):
        """get RIOT web console stats from XMLRPC"""

    def chk_snmp_validate_vesion(self):
        result = True
        mib = 'sysDescr'
        resp = self.cli("show version | match Junos:")
        m = re.search(r'Junos: (\S+)', resp)
        if m:
            ver_cli = m.group(1)
        else:
            return False
        resp = str(self.get_snmp(mib))
        m = re.search(r'JUNOS (\S+) \[', resp)
        if m:
            ver_snmp = m.group(1)
        else:
            ntlog("version obtained via snmp does not match." + \
                " Actual return is \n%s\n" % resp, logging.ERROR)
            return False
        return result and ver_snmp == ver_cli

    def set_riot_http(self):
        '''Enable RIOT Web Stats with password pfe/pfe'''
        result = False
        cmd = "/home/pfe/riot/vfp_util.sh -http_enable"
        riot_user = "pfe"
        riot_pass = "pfe"
        try:
            self.vfp.h.sendline(cmd)
            pattern = [self.vfp.h.PROMPT, 'Username:', 'Password:', 'HTTP Access Enabled']
            while True:
                idx = self.vfp.h.expect(pattern, timeout=self.timeout)
                if idx == 0:
                    break
                elif idx == 1:
                    self.vfp.h.sendline(riot_user)
                elif idx == 2:
                    self.vfp.h.sendline(riot_pass)
                elif idx == 3:
                    result = True
        except:
            result = False
            ntlog("Failed to enable RIOT HTTP with %s" % sys.exc_info()[0],
                level = logging.ERROR)
        if not result :
            ntlog("Failed to enable RIOT HTTP for unknown reason",
                level = logging.ERROR)
        return result

    def chk_vcp_vfp_access(self):
        """Check whether VFP can be accessed from VCP from shell
        via ssh -Ji 128.0.0.16.
        """
        vfp_em1_ip = "128.0.0.16"
        ssh_cmd = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        self.mode("shell")
        self.sendline(ssh_cmd + " -Ji -l root " + vfp_em1_ip)
        self.expect(self.PROMPT)
        os_name="Wind River Linux"
        os_version = self.cmd('cat /etc/os-release | grep "^NAME"')
        self.cmd("exit")
        return os_name in os_version

    def chk_if_type_support(self):
        result = True
        for if_type in ["xe", "et", "ge"]:
            result &= self.set_if_type(if_type)
        return result

    def set_if_type(self, if_type):
        """ set interface type to ge, xe or et. Return True if sccess"""
        if if_type not in ["ge", "xe", "et"]:
            ntlog("Interface type %s is not supported. " % if_type + \
                "It should be ge, xe or et.", logging.ERROR)
            return False
        cfg = "set chassis fpc 0 pic 0 interface-type " + if_type
        self.config(cfg)
        port_cnt = self.get_port_count(0, 0, if_type)
        if port_cnt > 0 :
            ntlog("there are %s %s interfaces" %(port_cnt, if_type))
            return True
        else:
            ntlog("Unable to set to %s interface type" % if_type, logging.ERROR)
            return False

    def set_port_count(self, port_cnt):
        """set interface port count. Return True if success"""
        if type(port_cnt) is not int or port_cnt > 96 or port_cnt < 1 :
            ntlog("port_cnt needs to be an integer between 1 and 96", logging.ERROR)
            return False
        cfg = "set chassis fpc 0 pic 0 number-of-ports %d" % port_cnt
        self.config(cfg)
        return port_cnt == get_port_count(0, 0)

    def get_port_count(self, fpc=0, pic=0, if_type="ge"):
        cmd = "show interfaces terse | match \"\(^%s-0/0\"" %  if_type + \
            " | except \"\\.\" | count"
        self.mode("cli")
        m = re.search("Count:\s+(\d+)\s+lines", self.cmd(cmd))
        return m.group(1)

    def set_lo0_fw_simple(self):
        cfg_grp_name = "LO0_FW"
        cfg_fw_name = "HOST_FW"
        cfg_lo0_fw = """term ACCEPT_ICMP from protocol icmp
term ACCEPT_ICMP then count ACCEPT_ICMP
term ACCEPT_ICMP then accept
term deny_u8000 from protocol udp
term deny_u8000 from destination-port 8000
term deny_u8000 then count DENY_U8000
term deny_u8000 then log
term deny_u8000 then syslog
term deny_u8000 then discard
term accept_t8000 from protocol tcp
term accept_t8000 from destination-port 8000
term accept_t8000 then count ACCEPT_T8000
term accept_t8000 then accept
term DEFAULT then accept"""
        cfg = ""
        for line in cfg_lo0_fw.split("\n"):
            cfg += "set groups " + cfg_grp_name + " firewall family inet " + \
                "filter " + cfg_fw_name + " " + line + "\n"
        cfg += "set groups lo0fw interfaces lo0 unit 0 family inet filter input " + cfg_fw_name + "\n"
        cfg += "set apply-groups " + cfg_grp_name
        self.config(cfg)

    def get_rsi(self):
        '''Request Support Information like summary for VMX in AWS'''
        inst_id = self.ec2inst.instance.instance_id
        client = self.ec2inst.client
        rsi = {'aws_inst': client.describe_instances(InstanceIds=[inst_id])}
        rsi['vcp_rsi'] = self.cli("request support information")
        rsi['vcp_cfg'] = self.cli("show configuration")
        riot_file = "vfp_riot_dump"
        resp = self.vfp.cmd("python /home/pfe/riot/riot_stats_logging.py -i localhost -f %s -n 2" % riot_file)
        m = re.search(r'(vfp_riot_dump_\d+)', resp)
        if m:
            rsi['riot_stats'] = self.vfp.cmd("cat " + m.group(1))
        else:
            rsi['riot_stats'] = "Unable to dump riot_stats due to " + resp
        filename = "aws_vmx_rsi_" + str(int(time.time()))
        f = open(filename, 'w')
        json.dump(rsi, f)
        #pp.pprint(rsi, stream=f)
        f.close()
        return rsi


def usage():
    print sys.argv[0] + " -v <vpc_name> -i <instance_name> -o <operation>"
    cmd_help = """
Vmx Test in AWS - A set of quick tasks via command line

Options
=======

 -o Operation  
    vpc_init        Initialize A VPC
    cleanup         Remove a given VPC and resources associated with it
    start-instance  Start an instance specified by -i or instances specified
                    by --instances
    stop-instance   Stop an instance specified by -i or instances specified by
                    --instances
    terminate       Terminate an instance specified by -i or instances specified
                    by --instances
    chk-sriov       Check whether SRIOV or Enhanced Networking is enabled for
                    the instance(s) specified by -i or --instances
    enable-sriov    Enable SRIOV or Enhanced Networking for the instance(s)
                    specified by -i or --instances
    set-vpc-peering Set Peering between two VPCs and create necessary routes
                    for reachability
    add-subnets     Create subnets. 
    create-security-groups
                    Create security groups predefined int and ext
    create-interfaces
                    Create interfaces for each subnet. The number of ENIs
                    to be created for each subnet is defined by --eni-per-subnet
    cfg-lnx-hosts   Install necessary packages and enable SR-IOV
    launch-ipsec-instances
                    Launch multiple pairs of VMXes for IPSec testing
                    Use --ipsecvmx to specify sequence of pairs to launch
                    0 - m4.xlarge
                    1 - m4.2xlarge
                    2 - m4.4xlarge
                    3 - m4.10xlarge
                    4 - c3.2xlarge
                    5 - c3.4xlarge
                    6 - c3.8xlarge
                    7 - c4.2xlarge
                    8 - c4.4xlarge
                    9 - c4.8xlarge
    vmx-install-license
                    Install licenses for VMX. Files specified via --license
    get-console-output
                    Dump console output for instances
    install-iperf3  Install iperf3 via git for Linux hosts
    vmx-basic-setup Preconfigure VMX from scratch including IPSec

 -i --instance      Instance name
 -v --vpc-name      VPC name

 --instances        a list of instances separated by ":"
 --rootpw           Root password for initial VMX config
 --instance-type    Type of instance
 --ami-vmx          AMI for VMX
 --vmx-license      A list of licenses to be preinstalled during config for 
                    for VMXes. Separated by ":"
 --ipsecvmx         sequence numbers separated by ":" for IPSec VMX pairs
 --vpcs             VPCs separated by ":"
 --gw-offset        Required for IPerf Test, which pair of VMX to use
 --eni-per-subnet   Number of ENIs to be created per Subnet
 --subnet-cnt       Number of Subnets to be created

"""
    print cmd_help

def main():

    try:
        opts, args = getopt.getopt(sys.argv[1:], 
            "hwi:o:v:", ["help", "instance=", "vpc=", "oper=", "instance-type=",
            "vmx-license=", "ami-vmx=", "inst-params=", "rootpw=", 
            "gw-offset=", "vpcs=", "subnet-cnt=", "instances=",
            "ipsecvmx=", "eni-per-subnet=",
            ])
    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit(2)
    inst_name, vpc_name, oper, ami_vmx= ['', '', '', '']
    inst_type, license = [vmx_inst_type, None]
    rootpw = None
    subnet_cnt = 0
    inst_params = []
    gw_offset = [0, 0]
    instances = []
    ipsec_vmx = []
    wait = False # wait for instance/vmx fully accessible
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit(1)
        elif opt == "-w":
            wait = True
        elif opt in ("-i", "--instance"):
            inst_name = arg
        elif opt in ("-v", "--vpc-name"):
            vpc_name = arg
        elif opt in ("-o", "--operation"):
            oper = arg
        elif opt in ("--instance-type"):
            inst_type = arg
        elif opt in ("--vmx-license"):
            license = arg
        elif opt in ("--ami-vmx"):
            ami_vmx = arg
        elif opt in ("--rootpw"):
            rootpw = arg
        elif opt in ("--inst-params"):
            inst_params.append(arg)
        elif opt in ("--gw-offset"):
            gw_offset = map(int, arg.split(":"))
        elif opt in ("--ipsecvmx"):
            ipsecvmx=map(int, arg.split(":"))
        elif opt in ("--vpcs"):
            vpcs = arg.split(":")
        elif opt in ("--subnet-cnt"):
            subnet_cnt = int(arg)
        elif opt in ("--eni-per-subnet"):
            eni_per_subnet = int(arg)
        elif opt in ("--instances"):
            instances = map(str, arg.split(":"))
    if '' in (inst_name + vpc_name, oper):
        usage()
        sys.exit(2)

    if inst_name != '' and len(instances) == 0:
        instances = [inst_name]
    vmxaws = VmxAws(vpc=vpc_name)
    if oper == "vpc_init":
        vmxaws.vpc_init()
    elif oper == "terminate":
        vmxaws.terminate_instance(instances)
    elif oper == "cleanup":
        vmxaws.vpc_cleanup()
    elif oper == "setup-all":
        vmxaws.setup_all(ami_vmx)
    elif oper == "install-iperf3":
        vmxaws.install_iperf3(instances)
    elif oper == "install-ixgbevf":
        vmxaws.install_ixgbevf(instances)
    elif oper == "cfg-iperf3-vmx":
        vmxaws.cfg_iperf3_vmx(instances)
    elif oper == "iperf3-bw":
        vmxaws.throughput_with_iperf3("xwu-lnx01", "xwu-lnx02", gw_offset)
    elif oper == "get-console-output":
        vmxaws.get_console_output(inst_name)
    elif oper == "start-instance":
        vmxaws.start_instance(instances, wait)
    elif oper == "stop-instance":
        vmxaws.stop_instance(instances)
    elif oper == "chk-sriov":
        vmxaws.chk_sriov(inst_name)
    elif oper == "enable-sriov":
        vmxaws.enable_sriov(instances)
    elif oper == "launch-vmx":
        vmxaws.setup_vmx(inst_name=inst_name, inst_type=inst_type, ami=ami_vmx)
    elif oper == "launch-vmxes":
        vmxaws._launch_two_vmx()
    elif oper == "vmx-install-license":
        vmxaws.vmx_install_license(inst_name=inst_name, licenses=license)
    elif oper == "launch-ipsec-instances":
        vmxaws.launch_ipsec_instances(inst_params, ipsecvmx=ipsecvmx)
    elif oper == "vmx-basic-setup":
        vmxaws.vmx_basic_setup(names=instances, rootpw=rootpw)
    elif oper == "vfp-http-enable":
        vmxaws.vfp_http_enable(name=inst_name)
    elif oper == "set-vpc-peering":
        vmxaws.set_vpc_peering(vpcs)
    elif oper == "launch-lnx-instances":
        vmxaws.launch_lnx_instances(inst_params)
    elif oper == "add-subnets":
        vmxaws.vpc_create_subnet(subnet_cnt)
    elif oper == "cfg-lnx-hosts":
        vmxaws.cfg_lnx_hosts(instances)
    elif oper == "create-security-groups":
        vmxaws.vpc_create_security_groups()
    elif oper == "create-interfaces":
        vmxaws.vpc_create_interface(eni_per_subnet)
    else:
        ntlog("unsupported operation " + oper)
        usage()


if __name__ == "__main__":
    #aec2 = awsec2.AwsEc2()
    #evpc = awsec2.Ec2Vpc(aec2=aec2, name="w01")
    #evpc.set_route_table_main_gw()
    #vmx = Vmx(host=aws_eips[0], user='root', ssh_key=key_file)
    main()
