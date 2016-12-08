import os,subprocess,sys,logging,json,ConfigParser
from nt import *
import VmxAws

try:
    import boto3
    import botocore
    from boto3.session import Session
except ImportError:
    err = sys.exc_info()[1]
    raise ImportError(str(err) + " boto3 required but not found")

__author__ = 'Sean Wu'
__email__ = 'xwu@xkey.org'
__copyright__ = 'Copyright 2003-2016, xkey.org'
__version__ = '0.1'
__revision__ = "1"
#__all__ = ['ExceptionPyNT', '__version__', '__revision__']

aws_credential = {}
VPC_CIDR_BLOCK = "192.168.128.0/17"
VPC_SUBNET_MASK = 24
VPC_ADDR_LOW = 4

def get_aws_credential(profile="default", cred_file = "~/.aws/credentials"):
    '''
    Obtain AWS credential using one of the following 
        - profile name
        - credential files using aws config
    '''
    config = ConfigParser.ConfigParser()
    config.read(os.path.expanduser(cred_file))
    return {'keyid': config.get(profile, 'aws_access_key_id'),
        'key': config.get(profile, 'aws_secret_access_key')}

def vmx_prepare(ec2, cidr, nameprefix, subnets):
    vmx = {}
    # Step 0 initialize
    vpc_name = nameprefix + "-vpc"
    client = ec2.meta.client

    # step 1 create VPC
    vpc0 = client.create_vpc(CidrBlock = cidr)
    vpcid = vpc0['Vpc']['VpcId']
    vpc1=ec2.Vpc(vpcid)
    vpc1.create_tags(Tags=[{'Key': 'Name', 'Value': vpc_name}])
    ntlog("VPC %s was created with Id of %s" % (vpc_name, vpcid))
    vmx['vpc_id'] = vpcid
    
    # step 2 create a security group and allows Safe Cidr
    secgrp_name = "%s-secgrp01" % nameprefix
    secgrp = client.create_security_group(GroupName=secgrp_name,
        Description="%s SecurityGroup" % nameprefix, VpcId = vpcid)
    secgrpId = secgrp['GroupId']
    sg01 = ec2.SecurityGroup(secgrpId)
    sg01.authorize_ingress(IpPermissions=[
        { 'IpProtocol': '-1', 'FromPort': -1, 'ToPort': -1,
        'IpRanges': [{'CidrIp': SAFE_NET}, {'CidrIp': SAFE_IP}]}])
    ntlog("Security Group %s was created with Id of %s" %(secgrp_name, secgrpId))
    sgroups = [secgrpId,]
    vmx['sg_ids'] = sgroups

    # step 3 create nets and ifs
    net_ids = []
    netif_ids = []
    for netid in range(len(subnets)):
        subnet0 = client.create_subnet(VpcId=vpcid, 
            CidrBlock=subnets[netid])
        ntlog("Subnet created in zone: %s" % 
            subnet0['Subnet']['AvailabilityZone'])
        subnetid = subnet0['Subnet']['SubnetId']
        subnet = ec2.Subnet(subnetid)
        netname = "%s-net%d" % (nameprefix, netid)
        subnet.create_tags(Tags=[{'Key': 'Name', 'Value': netname}])
        ntlog("Subnet %s with ID %s was created" % (netname, subnetid))
        net_ids.append(subnetid)
        ifname = "%s-if%d" % (nameprefix, netid)
        netif = ec2.create_network_interface(SubnetId = subnetid, 
            Description=ifname, Groups=sgroups)
        netif_id = netif.network_interface_id
        netif_ids.append(netif_id)
        ntlog("Network Interface %s with ID of %s" % (ifname, netif_id) + \
            " was created and attached to subnet %s with Id of %s" % \
            (netname, subnetid))
    vmx['net_ids'] = net_ids
    vmx['netif_ids'] = netif_ids

    # step 4 create gateway

    gw_name = "%s-gw01" % nameprefix
    inet_gw = client.create_internet_gateway()
    inet_gw_id = inet_gw['InternetGateway']['InternetGatewayId']
    inet_gw1 = ec2.InternetGateway(inet_gw_id)
    inet_gw1.create_tags(Tags=[{'Key': 'Name', 'Value': gw_name}])
    inet_gw1.attach_to_vpc(VpcId = vpcid)
    ntlog("Internet Gateway %s was created with Id of %s"%(gw_name,inet_gw_id))
    ntlog("Gateway is also attached to VPC %s" % vpcid)
    vmx['inet_gw'] = inet_gw_id
    
    # step 5 create routing table
    rtt_name = "%s-rtt1" % nameprefix
    rtts = client.describe_route_tables(Filters=[
        {'Name': 'vpc-id', 'Values': [vpcid]}])
    rtt_id = rtts['RouteTables'][0]['RouteTableId']
    rtt = ec2.RouteTable(rtt_id)
    rtt.create_route(DestinationCidrBlock='0.0.0.0/0', 
        GatewayId = inet_gw_id)
    rtt.create_tags(Tags=[{'Key': 'Name', 'Value': rtt_name}])
    ntlog("Route Table %s was created with Id of %s" % (rtt_name, rtt_id))
    ntlog("Default route towards gateway was added to table %s" % rtt_name)

    vmx['rtt_id'] = rtt_id
    # Step 6 create an elastic IP

    eip = client.allocate_address(Domain='vpc')
    return vmx

def throttle(api_call, MAX_RETRY=8, **kargs):
    '''Generic handling of Request Limit Exceeded exception'''

    if not callable(api_call):
        ntlog("throttle: api_call has to be a function or method", 
            level=logging.ERROR)
        return None
    retry = True
    retries = 0
    result = None

    while retry and retries < MAX_RETRY:
        try:
            result = api_call(**kargs)
            retry = False
        except botocore.exceptions.ClientError as e:
            # RequestLimitExceeded :
            if e.response['Error']['Code'] != 'RequestLimitExceeded':
                ntlog("Unexpceted error:" + str(sys.exc_info()[0]) + ' ' + \
                str(e.response['Error']['Code']))
                raise
            interval = 2 ** retries
            ntlog("%s %s. retry# %d after %d seconds for API Call %s" % \
                (sys.exc_info()[0], str(e.response['Error']['Code']),
                retries + 1, interval, api_call.__name__),
                level=logging.WARNING)
            sleep(interval)
            retries += 1
            retry = True
    return result

#instances = ec2.instances.filter(
#    Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
#
#cnt_inst = 0
#for instance in instances:
#    cnt_inst += 1
#    print(instance.id, instance.instance_type)
#    print (instance)
#print "total number of instances is %d" % cnt_inst
#for status in ec2.meta.client.describe_instance_status()['InstanceStatuses']:
#    print(status)
#vmx_terminate(name=vmx_inst_name, ec2=ec2)

# Cleanup
#vmx_cleanup(ec2=ec2, nameprefix = vmx_name_prefix)
# create all resources in order to launch vmx
#vmx = vmx_prepare(ec2=ec2, nameprefix=vmx_name_prefix, cidr=vmx_vpc_cidr, 
#    subnets=vmx_subnets)


# create eslastic IP, security group, associate address
# 192.168.0.0/16 (VPC) and from Juniper (NAT)
# Create 2nd instance of VPC (traffic from 2nd eslastic IP)
# create security for each rule and chain them together
# change security group when creating network interfaces
# use same security group and specify network interface created in previous
# step when launching instance
# 

class Ec2Instance(object):
    """
    Manage EC2 Instance. Another approach to extend ec2.Instance
        - https://aws.amazon.com/ec2/instance-types/
        - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html
    """
    inst_types = {
        'm3.xlarge': {'vcpu': 4, 'mem': 15, 'storage': 'SSD', 'eni': 4},
        'm3.2xlarge': {'vcpu': 8, 'mem': 30, 'storage': 'SSD', 'eni': 4},
        'm4.xlarge': {'vcpu': 4, 'mem': 16, 'storage': 'EBS', 'eni': 4},
        'm4.2xlarge': {'vcpu': 8, 'mem': 32, 'storage': 'EBS', 'eni': 4},
        'm4.4xlarge': {'vcpu': 16, 'mem': 64, 'storage': 'EBS', 'eni': 8},
        'm4.10xlarge': {'vcpu': 40, 'mem': 160, 'storage': 'EBS', 'eni': 8},
        'c3.xlarge': {'vcpu': 4, 'mem': 7.5, 'storage': 'SSD', 'eni': 4},
        'c3.2xlarge': {'vcpu': 8, 'mem': 15, 'storage': 'SSD', 'eni': 4},
        'c3.4xlarge': {'vcpu': 16, 'mem': 30, 'storage': 'SSD', 'eni': 8},
        'c3.8xlarge': {'vcpu': 32, 'mem': 60, 'storage': 'SSD', 'eni': 8},
        'c4.xlarge': {'vcpu': 4, 'mem': 7.5, 'storage': 'EBS', 'eni': 4},
        'c4.2xlarge': {'vcpu': 8, 'mem': 15, 'storage': 'EBS', 'eni': 4},
        'c4.4xlarge': {'vcpu': 16, 'mem': 30, 'storage': 'EBS', 'eni': 8},
        'c4.8xlarge': {'vcpu': 36, 'mem': 60, 'storage': 'EBS', 'eni': 8},
    }
    InstanceState = {
        'pending' :         0,
        'running' :         16,
        'shutting-down' :   32,
        'terminated' :      48,
        'stopping' :        64,
        'stopped' :         80,
    }
    EnhancedNetworking = ['c3', 'c4', 'd2', 'i2', 'm4', 'r3']
    eni_10g = ['m4.10xlarge', 'c3.8xlarge', 'c4.8xlarge']

    def __init__(self, evpc, inst_id = None, inst_type = None, 
        key_name = None, ami_id = None, enis = None, name = None,
        # typically not passed over
        min_count = 1, max_count = 1, 
        monitor_enable = False, inst_shutdown_behavior = 'stop', 
        disable_api_termination = False,
        placement = {}
        ):
        '''
        A pseudo child class of Instance. 
        An instance of Ec2Vpc is the only required argument passed to evpc
        '''
        # Required arguments
        self.evpc = evpc
        # primary
        self.ami_id = ami_id
        self.name = name
        # derived
        self.pips = [] # private IPs
        self.enis = []
        self.aec2 = self.evpc.aec2
        self.ec2 = self.aec2.ec2
        self.client = self.ec2.meta.client
        self.instance = None
        self.placement = placement

        if inst_id is not None:
            inst = self.ec2.Instance(inst_id)
            self.instance = inst
            self.name = inst_id
            if inst.tags is not None:
                for tag in inst.tags:
                    if tag['Key'] == 'Name':
                        self.name = tag['Value']
            nifs = {}
            for nif in inst.network_interfaces_attribute:
                nifs[nif["Description"]] = \
                    self.ec2.NetworkInterface(nif["NetworkInterfaceId"])
            for nif_desc in sorted(nifs):
                self.enis.append(nifs[nif_desc])
                self.pips.append(nifs[nif_desc].private_ip_address)

        else:
            nifs = []
            self.enis = enis
            for nid in range(len(enis)):
                nif_descr = "eth%s" % nid
                nifs.append(
                    {'NetworkInterfaceId': enis[nid].network_interface_id,
                    'DeviceIndex': nid, 'Description': nif_descr})
                self.pips.append(enis[nid].private_ip_address)
            ntlog("Now launching instance %s using AMI %s" % (name, ami_id))
            timer = Timer("Launch Instance %s" % name)
            inst = self.ec2.create_instances(
                ImageId = ami_id, InstanceType = inst_type, KeyName = key_name,
                NetworkInterfaces = nifs,
                # optional
                MinCount = min_count, MaxCount = max_count, 
                Monitoring={'Enabled': monitor_enable},
                DisableApiTermination=disable_api_termination, 
                InstanceInitiatedShutdownBehavior=inst_shutdown_behavior,
                Placement=placement,
                )[0]
            ntlog("Instance %s lauched with ID %s" % (name, inst.instance_id))
            self.instance = inst
            timer.update("Instance launched, waiting for running")
            inst.wait_until_running()
            ntlog("Instance %s is now running" % name)
            #waiter = self.client.get_waiter("instance_running")
            #waiter.wait(InstanceId = inst.instance_id)
            throttle(inst.create_tags, Tags=[{'Key': 'Name', 'Value': name}])
            timer.stop()
        evpc.ec2instances[self.name] = self

    def terminate(self):
        """Terminate wait until it is completed
        """
        ntlog("Instance %s with Id of %s is being terminated" % \
            (self.name, self.instance.instance_id))
        self.instance.delete_tags(Tags=[{'Key': 'Name', 'Value': self.name}])
        self.instance.terminate()
        self.instance.wait_until_terminated()

    def start(self):
        """Start an instance if stopped, return until running"""
        state = self.instance.state
        if state['Code'] != Ec2Instance.InstanceState['stopped']:
            ntlog("Instance is in %s state, start aborted" % state['Name'])
            return False
        ntlog("Instance %s with Id of %s is being started" % \
            (self.name, self.instance.instance_id))
        timer = Timer("Start VMX")
        self.instance.start()
        self.instance.wait_until_running()
        timer.stop()

    def enable_sriov(self):
        '''Enable SR-IOV mode for Enhanced Network. This can be called only when the instance is stopped'''
        state = self.instance.state
        if state['Code'] != Ec2Instance.InstanceState['stopped']:
            ntlog("Instance is in %s state." % state['Name'] + \
                " Enabling SRIOV mode requires" + \
                " that the instance is stopped. Aborted")
            return False
        #attribute = self.client.describe_instance_attribute(
        #    InstanceId = self.instance.instance_id,
        #    Attribute="sriovNetSupport")
        #if attribute['SriovNetSupport']['Value'] == 'simple':
        if self.chk_sriov():
            ntlog("Instance %s is already enabled with SRIOV support" % \
                self.name)
            return True
        if self.instance.virtualization_type != 'hvm':
            ntlog("SRIOV is only supported with HVM virtualization. %s is " + \
                "not currently supported" % self.instance.virtualization_type)
            return False
        ntlog("Enabling SRIOV Mode for %s" % self.name)
        #self.instance.modify_attribute(
        #    SriovNetSupport={'Value': 'simple'},
        #    )
        self.client.modify_instance_attribute(
            InstanceId = self.instance.instance_id,
            SriovNetSupport={'Value': 'simple'},
            )
        return self.chk_sriov()


    def chk_sriov(self):
        '''Check whether the instance is enabled with SRIOV, or enhanced 
        networking. It will reload the attributes first, as there could 
        be a discrepancy in cached state of instance'''
        #ntlog(msg=self.instance.sriov_net_support, level=logging.DEBUG)
        #return self.instance.sriov_net_support == 'simple'
        attr = self.client.describe_instance_attribute(
            InstanceId = self.instance.instance_id,
            Attribute="sriovNetSupport",
            )['SriovNetSupport']
        sriov = False
        if 'Value' in attr and attr['Value'] == "simple":
            sriov = True
        return sriov

    def stop(self):
        """Stop an instance if running, return until stopped"""
        state = self.instance.state
        if state['Code'] != Ec2Instance.InstanceState['running']:
            ntlog("Instance is in %s state, stop aborted" % state['Name'])
            return False
        ntlog("Instance %s with Id of %s is being stopped" % \
            (self.name, self.instance.instance_id))
        timer = Timer("Stop VMX")
        self.instance.stop()
        self.instance.wait_until_stopped()
        timer.stop()

    def install_iperf3(self, key):
        ''' for an EC2 instance launched from AMI, necessary packages
        need to be installed including iperf3 from git/repository
        it also installs several other packages for performance testing

            hping3: for host path traffic generation

        '''
        install_cmd = """sudo apt-get -y update
sudo apt-get -y upgrade
sudo apt-get -y install git make gcc hping3
git clone https://github.com/esnet/iperf
cd iperf
./configure
sudo make
sudo make install
sudo make clean
sudo ldconfig"""
        install_cmd += "\nsudo ifconfig eth1 %s/24 up" % self.pips[1]
        # netmask needs to be updated not hard coded
        ip = self.instance.public_ip_address
        if ip is None:
            ip = self.instance.private_ip_address
        host = NT(host = ip, os = 'linux', user = 'ubuntu', ssh_key = key)
        cmds = install_cmd.split("\n")
        host.cmd(cmd=cmds, timeout=600)
        host.set_hostname(self.name)

    def install_ixgbevf(self, key, version="2.16.4"):
        '''Enable SR-IOV aka enhanced networking, install 

            * apt-get update
            * apt-get install -y dkms
            * install ixgbevf and enabled with dkms with kernel upgrade

        http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking.html
        '''
        install_cmd = """sudo apt-get -y update
sudo apt-get -y upgrade
sudo apt-get -y install dkms"""
        cmds = install_cmd.split("\n")
        cmds.append("wget \"sourceforge.net/projects/e1000/files/" + \
            "ixgbevf stable/" + version + "/ixgbevf-" + version +".tar.gz\"")
        cmds.append("tar -xzf ixgbevf-" + version +".tar.gz")
        cmds.append("sudo mv ixgbevf-" + version + " /usr/src/")
        cmds.append("wget --no-check-certificate https://raw.githubusercontent.com/xmwu/pynt/master/misc/aws/ixgbevf_dkms.conf -O ixgbevf_dkms.conf")
        cmds.append('sed -i -e "s/VERSION_IXGBEVF/' + version + \
            '/g" ixgbevf_dkms.conf')
        cmds.append("sudo mv ixgbevf_dkms.conf /usr/src/ixgbevf-" + version + \
            "/dkms.conf")
        cmds.append("sudo dkms add -m ixgbevf -v " + version)
        cmds.append("sudo dkms build -m ixgbevf -v " + version)
        cmds.append("sudo dkms install -m ixgbevf -v " + version)
        cmds.append("sudo update-initramfs -c -k all")
        cmds.append("modinfo ixgbevf")
        cmds.append("/bin/rm -rf ixgbevf*.tar.gz ixgbevf_dkms.conf")
        eip = self.instance.public_ip_address
        host = NT(host=eip, os="linux", user="ubuntu", ssh_key=key)
        host.cmd(cmd=cmds, timeout=600)

    def cfg_eth(self, key, ifid):
        cmd = "sudo ifconfig eth%d up %s/%s" % (ifid, self.pips[ifid], 
            get_mask(self.enis[ifid].subnet.cidr_block))
        ip = self.instance.public_ip_address
        if ip is None:
            ip = self.instance.private_ip_address
        host = NT(host = ip, os = 'linux', user = 'ubuntu', ssh_key = key)
        host.cmd(cmd=cmd, timeout=600)

class Ec2Vpc(object):
    """AWS VPC Object, another way to extend boto3
    An Ec2Vpc object contains multiple necessary resources
    """
    def __init__(self, aec2, vpcid=None, name=None, cleanup=0, 
        cidr = VPC_CIDR_BLOCK, subnet_mask=VPC_SUBNET_MASK,
        addr_low = VPC_ADDR_LOW):
        self.aec2 = aec2
        self.ec2 = aec2.ec2
        self.addr_low = addr_low
        self.client = aec2.client
        self.vpcid = vpcid
        self.name = name
        self.vpc = None
        self.cidr = cidr
        self.enis = {}
        self.subnet_mask= int(subnet_mask)
        if vpcid is None and name is None:
            ntlog('Ec2Vpc requires requires either vpcid or vpc name ' + \
                'to be specified in arguments')
            sys.exit()
        elif vpcid is not None and name is not None:
            if (vpcid != aec2.vpcid_by_name(name)):
                ntlog("VpcId %s does not match VpcName %s. Exiting" % \
                    (vpcid, name))
                sys.exit()
        elif vpcid is None :
            self.vpcid = aec2.vpcid_by_name(name)
        else :
            self.name = aec2.vpcname_by_id(vpcid)
        
        if self.vpcid is None:
            self.vpc = self.ec2.create_vpc(CidrBlock = cidr)
            self.vpc.create_tags(Tags=[{'Key': 'Name', 'Value': name}])
            self.vpcid = self.vpc.vpc_id
        else :
            self.vpc = self.ec2.Vpc(self.vpcid)
        self.sgs = self.get_security_groups()
        self.set_security_groups_basic()
        self.nets = self.get_subnet() # NETS ID's
        self.nets_cidr=self.get_subnet_cidr() # 
        self.gw = self.get_internet_gateway()
        self.rtts = self.get_route_tables()
        [cidr_net, cidr_mask] = self.cidr.split("/")
        lo0_net_dec = ip2decimal(cidr_net) + (2 ** (32-self.subnet_mask)) * \
            (2 ** (int(self.subnet_mask) - int(cidr_mask)) - 1)
        self.lo0_net = decimal2ip(lo0_net_dec)
        gre_net_dec = lo0_net_dec - 2 ** self.subnet_mask
        self.gre_nets = get_subnets(base = decimal2ip(gre_net_dec) + "/" + \
                str(self.subnet_mask), mask = 30)
        self.ec2instances = {}
        self.update_ec2instances()

    def update_ec2instances(self):
        """If VPC exists already in AWS, it refreshes resources assignment"""
        for inst in self.vpc.instances.all():
            inst_id = inst.instance_id
            ec2inst = Ec2Instance(evpc = self, inst_id = inst_id)

    def get_route_tables_cnt(self):
        '''Get number of AWS EC2 rout tables'''
        rtts = self.ec2.route_tables.all()
        rtt_cnt = 0
        for rtt in rtts:
            rtt_cnt += 1
        return rtt_cnt

    def add_route(self, rtt, cidr, gw_type, gw_id, replace=True):
        '''Add a new route. By default, old route is deleted if already 
        existed. Supported gw_type are

            'Gateway', 'Instance', 'NetworkInterface',
            'VpcPeeringConnection', 'NatGateway'

        '''
        gw_type_supported = ['Gateway', 'Instance', 'NetworkInterface',
            'VpcPeeringConnection', 'NatGateway']
        if gw_type not in gw_type_supported:
            return False
        for rt in rtt.routes:
            if rt.destination_cidr_block == cidr:
                ntlog("Route %s already existed, deleting now" % cidr,
                    logging.WARNING)
                rt.delete()
        rtt.reload()
        gw = {gw_type + "Id": gw_id}
        rtt.create_route(DestinationCidrBlock = cidr, **gw)


    def add_route_tables(self, cnt):
        """ Add route_table up to number of <cnt> """
        rtt_cnt = self.get_route_tables_cnt()
        if rtt_cnt >= cnt :
           ntlog("Already %d route tables, no more added" % rtt_cnt)
           return False 
        for rid in range(rtt_cnt, (rtt_cnt + cnt)):
            rtt = self.ec2.create_route_table(VpcId = self.vpcid)
            rtt_name = "rtt-" + self.name + "-" + str(rid)
            rtt.create_tags(Tags=[{'Key': 'Name', 'Value': rtt_name}]) 
        return True

    def set_route_table_main_gw(self):
        """Associate internet gateway to the main route table of the VPC"""
        try:
            self.gw
        except:
            print "gateway is not yet defined, existing"
            return False

        rtt_name = "rtt-" + self.name
        rtt_main = self.ec2.route_tables.filter(Filters=[
            {'Name': 'vpc-id', 'Values': [self.vpcid]},
            {'Name': 'association.main', 'Values': ['true']},
            ])
        if len(list(rtt_main)) != 1 :
            ntlog("main route table not found")
            sys.exit()
        rttm = list(rtt_main)[0]
        rttm.create_tags(Tags=[{'Key': 'Name', 'Value': rtt_name}])
        rt_default = False
        cidr_default = '0.0.0.0/0'
        for route in rttm.routes:
            #if route['DestinationCidrBlock'] == cidr_default:
            if route.destination_cidr_block == cidr_default:
                self.client.replace_route(RouteTableId = rttm.route_table_id,
                    DestinationCidrBlock = cidr_default,
                    GatewayId = self.gw.internet_gateway_id)
                rt_default = True
        if not rt_default:
            rttm.create_route(DestinationCidrBlock='0.0.0.0/0',
                GatewayId = self.gw.internet_gateway_id)
        ntlog("Main route table now has default route set to internet gateway")
        return True

    def get_route_tables(self):
        '''Get route tables associated with this VPC by name'''
        #api_call = "self.ec2.route_tables.filter(Filters=[" + \
        #    "{'Name': 'vpc-id', 'Values': [" + self.vpcid + "]}," + \
        #    "])"
        rtts = throttle(self.ec2.route_tables.filter, 
            Filters=[{'Name': 'vpc-id', 'Values': [self.vpcid]}])
        #rtts = self.ec2.route_tables.filter(Filters=[
        #    {'Name': 'vpc-id', 'Values': [self.vpcid]},
        #    ])
        return list(rtts)

    def get_internet_gateway(self):
        """return internet gateway, if not existed, create and return new one"""
        gw_name = "gw-" + self.name
        gw = self.ec2.internet_gateways.filter(Filters=[{'Name': 
            'attachment.vpc-id', 'Values': [self.vpcid]}])
        inetgw = None
        if len(list(gw)) == 0:
            inetgw = self.ec2.create_internet_gateway()
            inetgw.attach_to_vpc(VpcId = self.vpcid)
            ntlog("Created new internet gateway %s and attach to VPC" \
                % inetgw.internet_gateway_id)
        else:
            inetgw = list(gw)[0]
            ntlog("Internet gateway %s already exists and is attached to VPC" \
                % inetgw.internet_gateway_id)
        throttle(inetgw.create_tags, Tags=[{'Key': 'Name', 'Value': gw_name}])
        return inetgw

    def get_subnet(self):
        '''Get a list of subnets for this VPC'''
        nets = {}
        for net in self.vpc.subnets.all():
            nets[net.cidr_block] = net
        subnets = []
        for cidr in sorted(nets):
            subnets.append(nets[cidr])
            for nif in nets[cidr].network_interfaces.all():
                self.enis[nif.private_ip_address] = nif
        return subnets

    def get_subnet_count(self):
        '''return number of subnets for the given VPC'''
        return len(self.nets)

    def get_subnet_cidr(self):
        '''
        Return a dictionary of {cidr_block: subnet object}
        '''
        nets = {}
        for net in self.vpc.subnets.all():
            nets[net.cidr_block] = net
        return nets

    def add_subnets(self, cnt):
        '''Add cnt number of new subnets'''
        cnt_curr = len(self.nets)
        ntlog("there are %d subnets in VPC already" % cnt_curr)
        ntlog("Adding %d more subnets now" % cnt)
        subnets = get_subnets(base=self.cidr, mask=self.subnet_mask,
            num=cnt+cnt_curr)
        for nid in range(cnt_curr, cnt_curr+cnt):
            subnet = self.vpc.create_subnet(CidrBlock = subnets[nid])
            net_name = self.name + "-net" + str(nid)
            throttle(subnet.create_tags, 
                Tags=[{'Key': 'Name', 'Value': net_name}])
            self.nets.append(subnet)
            self.enis[nid] = {}
        self.nets_cidr = self.get_subnet_cidr()

    def add_if(self, ip, sgs=[], srcChk=False, desc=None):
        '''
        Create interfaces where ip is address/mask, so that interface
        can be created in the correct subnet. if the ip is provided 
        without mask, default subnet_mask is used
        ip can also be a list of ["ip_addr/netmask"], where the first one
        is the primary private IP, and the remainings are secondary
        Return: NetworkInterafce Object
        '''
        nif = None
        
        ipaddrs = ip
        ips = []
        mask = self.subnet_mask
        pip_addresses = []
        if type(ip) is not list:
            ipaddrs = [ip]
        for addidx in range(len(ipaddrs)):
            elem = ipaddrs[addidx]
            if "/" in elem:
                pipadd = strip_mask(elem)
                if addidx == 0 :
                    mask = get_mask(elem)
            else:
                pipadd = elem
            pip_addresses.append({'PrivateIpAddress': pipadd,
                        'Primary': addidx == 0})
        pip = pip_addresses[0]['PrivateIpAddress']
        ntlog("Adding network interface with private ip of %s" % pip)
        net = get_network("/".join((pip, str(mask))))
        if pip in self.enis:
            ntlog("Network Interface for %s already exists, skipping..." % pip)
            nif = self.enis[pip]
            #should we add secondary?
        else:
            if desc is None:
                octets = pip.split(".")
                desc = "_".join((self.name, octets[2], octets[3]))
            nif = throttle(self.nets_cidr[net].create_network_interface,
                Description = desc,
                Groups = sgs,
                PrivateIpAddresses = pip_addresses)
            if nif is not None:
                self.enis[pip] = nif
                throttle(nif.create_tags, Tags=[{'Key': 'Name', 'Value': desc}])
                throttle(nif.modify_attribute,
                    SourceDestCheck = {'Value': srcChk})
            else:
                ntlog("Failed to create Network Interface %s" % pip,
                    level=logging.ERROR)
        return nif

    def add_if_safe2(self, ip, sgs=[], srcChk=False, desc=None, MAX_RETRY=8):
        """add Elastic Network Interface
        
        ip: Private IP address. this can be either a 
        single string of IP address, or a list of addresses. The address
        can be the x.x.x.x/mask_length or the address itself. If latter,
        the default subnet_mask for VPC is used.

        sgs: a name list of security groups.

        srcCheck: A boolean value to enable or disable source destination.
        AWS has this enabled by default, due to networking nature, it is 
        disabled by default for this API so that the interface can
        receive and send packets that are not destined to itself.

        desc: this is used for both description and Name field for the 
        interface. If None is passed, the default name for the interface is
        <vpc_name>_<3rd_octet>_<4th_octet>

        add_if_safe refers to exponential back off algrithm required to avoid
        RequestLimitExceeded botocore.exceptions.ClientError
        """
        retry = True
        retries = 0
        nif = None
        while retry and retries < MAX_RETRY:
            try:
                retry = False
                nif = self.add_if(ip, sgs, srcChk, desc)
            except botocore.exceptions.ClientError as e:
                # RequestLimitExceeded :
                interval = 2 ** retries
                if type(ip) is list:
                    pip = ip[0]
                else:
                    pip = ip
                ntlog("ADD ENI %s %s. retry# %d after %d seconds"
                    % (sys.exc_info()[0], str(e.response['Error']['Code']),
                     retries + 1, interval), level=logging.WARNING)
                sleep(interval)
                self.del_if_safe(pip)
                retries += 1
                retry = True
        return nif

    def add_pip(self, ip, ip2):
        """
        Add a secondary IP to elastic network interface with address of ip
        """
        try:
            eni = self.enis[ip]
        except:
            ntlog("ENI with address of %s does not exist" % ip, leve=logging.ERROR)
            return False
        eni.assign_private_ip_addresses(PrivateIpAddresses=[ip2])
        ntlog("%s is now assigned to ENI with primary private ip of %s" % \
            (ip2, ip))
        return True
            
    def get_security_groups(self):
        '''Get a list of security groups'''
        sgs = {}
        for sg in self.client.describe_security_groups(Filters = [
            {'Name': 'vpc-id', 'Values': [self.vpcid]}])['SecurityGroups']:
            sgs[sg['GroupName']] = self.ec2.SecurityGroup(sg['GroupId'])
        return sgs

    def set_security_groups_basic(self, cidr_ext=["0.0.0.0/0"]):
        if 'ext-pub' not in self.sgs:
            ipRanges = []
            for cidr in cidr_ext:
                ipRanges.append({'CidrIp': cidr})
            sg = self.vpc.create_security_group(
                GroupName="ext-pub", Description="External Public")
            sg.authorize_ingress(IpPermissions=[
                { 'IpProtocol': '-1', 'FromPort': -1, 'ToPort': -1,
                'IpRanges': ipRanges}])
            self.sgs['ext-pub'] = sg
            ntlog("Security Group ext-pub created to allow trusted network")
        if 'int-vpc' not in self.sgs:
            sg = self.vpc.create_security_group(
                GroupName="int-vpc", Description="VPC Internal")
            sg.authorize_ingress(IpPermissions=[
                { 'IpProtocol': '-1', 'FromPort': -1, 'ToPort': -1,
                'IpRanges': [{'CidrIp': self.cidr}]}])
            self.sgs['int-vpc'] = sg
            ntlog("Security Group int-vpc created to allow internal traffic")
        return True

    def get_address_allocation_id(self, pub):
        allocation_id = None
        for addr in self.client.describe_addresses(PublicIps=[pub])['Addresses']:
            allocation_id = addr['AllocationId']
        return allocation_id

    def get_route_table_main(self):
        '''return the main route table for the VPC'''
        rtts = self.ec2.route_tables.filter(Filters = [
            {'Name': 'vpc-id', 'Values': [self.vpcid]},
            {'Name': 'association.main', 'Values': ['true']},
            ])        
        rtt_cnt = 1
        rtt_main = None
        for rtt in rtts:
            if rtt_cnt == 1:
                rtt_main = rtt
                ntlog("Returning main routing table with ID %s" % 
                    rtt.route_table_id)
            else:
                rtt_cnt += 1
                ntlog("ERROR: more than 1 main route tables exist.")
        return rtt_main

    def del_if(self, pip):
        '''Delete Elastic Network Interface with Private IP of pip'''
        if pip not in self.enis:
            ntlog("ENI %s does not exist, aborting" % pip, logging.WARNING)
        else:
            ntlog("Deleting Elastic Network Interface %s with Private IP of %s" 
                % (self.enis[pip].network_interface_id, pip))
            try:
                self.enis[pip].reload()
            except botocore.exceptions.ClientError:
                ntlog("DEL IF - IF may not exist", logging.WARNING)
                del self.enis[pip]
                return False
            self.enis[pip].delete()
            del self.enis[pip]

    def del_if_safe(self, pip, MAX_RETRY=8):
        '''Delete ENI with graceful handling of RETRY_LIMIT_EXCEEDED'''
        retry = True
        retries = 0
        if pip not in self.enis:
            ntlog("ENI %s does not exist, aborting" % pip, logging.WARNING)
            return True
        while retry and retries < MAX_RETRY:
            try:
                self.del_if(pip)
                retry = False
            except botocore.exceptions.ClientError:
                # RequestLimitExceeded :
                interval = 2 ** retries
                ntlog("DEL ENI RequestLimitExceeded %s. retry# %d after %d seconds"
                    % (sys.exc_info()[0], retries + 1, interval),
                    level=logging.WARNING)
                sleep(interval)
                retries += 1
                retry = True
        return retries < MAX_RETRY
                


    def cleanup(self):
        '''Clean VPC and its dependencies. 

            * Terminate all instances
            * Disassociate elastic IPs
            * Delete elastic network interfaces
            * Delete all subnets
            * Detach and delete internet gateway from VPC
            * Delete all security groups
            * Delete all route tables except the main one
            * And finally delete VPC itself
        '''
        status = True
        for e2inst in self.ec2instances:
# how to update a tag, change name to "terminated-" before terminate
            self.ec2instances[e2inst].terminate()
        self.ec2instances = {}
        self.aec2.disassociate_eips(vpc_name=self.name)
        for pip in self.enis.keys():
            self.del_if(pip)
        self.enis = {}
        for net in self.nets :
            ntlog("Deleting Subnet %s with CIDR of %s" % \
                (net.subnet_id, net.cidr_block))
            net.delete()
        self.nets = []
        self.nets_cidr = {}
        ntlog("Detaching and deleting Internet Gateway %s" % \
            self.gw.internet_gateway_id)
        self.gw.detach_from_vpc(VpcId = self.vpcid)
        self.gw.delete()
        self.gw = None
        for sg in self.sgs:
            if sg == 'default':
                #ntlog("Ignore Security Group default, moving on...")
                continue
            ntlog("Deleting Security Group %s" % sg)
            self.sgs[sg].delete()
        self.sgs = None
        ntlog("Checking non-main route tables for vpc %s" % self.name) 
        rtts = self.ec2.route_tables.filter(Filters = [
            {'Name': 'vpc-id', 'Values': [self.vpcid]},
            ])
        rtt_main = self.get_route_table_main()
        for rtt in rtts :
            if rtt.route_table_id != rtt_main.route_table_id :
                ntlog("Deleting route table %s" % rtt.route_table_id)
                rtt.delete()
        self.rtts = []
        peering_ids = self.aec2.get_vpc_peering(vpc_name=self.name)
        status &= self.aec2.del_vpc_peering(peering_ids)
        ntlog("Deleting existing VPC %s" % self.name)
        self.vpc.delete()
        return status

    def get_throughput(self, host1, host2, key, gw_offset=[0, 0], 
        ifidx=[1, 2], mss=1448):
        '''
        Run the iperf3 throughput test. TCP only for now
        gw_offset refers to vmx gw address offset from low addr 
        ifidx refers to lnx host interface id
        '''
        pub_add = []
        pvt0_add = []
        pvt_add = []
        pvt_gw = []
        hosts = [host1, host2]
        vmx=[]
        host_type = []
        for idx in range(2):
            inst = self.ec2instances[hosts[idx]]
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
                 self.addr_low + gw_offset[idx])
            pvt_gw.append(gw)
            # needs to be moved to VmxAws
            vmx_name = "vmx%02d" % gw_offset[idx]
            vmx.append(VmxAws.Vmx(self.ec2instances[vmx_name]))
        iperf = IPerf(server=pub_add[0], client=pub_add[1], user="ubuntu",
           key=key)
        iperf.connect()
        iperf.start_server()
        #iperf.get_bandwidth(udp=True)
        results = []
        # needs to be moved to VmxAws
        for grp in ["no_vmx", "direct", "ipsec"]:
            ntlog("Testing Throughput with %s connection" % grp)
            if grp == "no_vmx":
                iperf.config(saddr=pvt0_add[0], caddr=pvt0_add[1])
            else :
                cfg = "delete apply-groups direct\n"
                cfg += "delete apply-groups ipsec\n"
                cfg += "set apply-groups " + grp
                for v in vmx:
                    v.config(cfg)
                iperf.config(saddr=pvt_add[0], caddr=pvt_add[1], 
                    sgateway=pvt_gw[0], cgateway=pvt_gw[1])
            result = iperf.get_bandwidth()
            for record in result:
                record['dut_type'] = grp
                record['host_type'] = host_type[0]
                record['vmx_type'] = vmx[0].inst_type
                results.append(record)
        return results

    def get_thruput(self, host1, host2, key, gw_offset=[0, 0], 
        ifidx=[1, 2], mss=1448):
        '''
        Run the iperf3 throughput test. TCP only for now
        gw_offset refers to vmx gw address offset from low addr 
        ifidx refers to lnx host interface id
        '''
        pub_add = []
        pvt0_add = []
        pvt_add = []
        pvt_gw = []
        hosts = [host1, host2]
        vmx=[]
        host_type = []
        for idx in range(2):
            inst = self.ec2instances[hosts[idx]]
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
                 self.addr_low + gw_offset[idx])
            pvt_gw.append(gw)
            # needs to be moved to VmxAws
            vmx_name = "vmx%02d" % gw_offset[idx]
            vmx.append(VmxAws.Vmx(self.ec2instances[vmx_name]))
        iperf = IPerf(server=pub_add[0], client=pub_add[1], user="ubuntu",
           key=key)
        iperf.connect()
        iperf.start_server()
        #iperf.get_bandwidth(udp=True)
        results = []
        # needs to be moved to VmxAws
        for grp in ["no_vmx", "direct", "ipsec"]:
            ntlog("Testing Throughput with %s connection" % grp)
            if grp == "no_vmx":
                iperf.config(saddr=pvt0_add[0], caddr=pvt0_add[1])
            else :
                cfg = "delete apply-groups direct\n"
                cfg += "delete apply-groups ipsec\n"
                cfg += "set apply-groups " + grp
                for v in vmx:
                    v.config(cfg)
                iperf.config(saddr=pvt_add[0], caddr=pvt_add[1], 
                    sgateway=pvt_gw[0], cgateway=pvt_gw[1])
            result = iperf.get_bandwidth()
            for record in result:
                record['dut_type'] = grp
                record['host_type'] = host_type[0]
                record['vmx_type'] = vmx[0].inst_type
                results.append(record)
        return results

class AwsEc2(object):
    '''Amazon Web Services (AWS) Elastic Cloud Computing (EC2)
    A session to manage a collection of EC2 resources
    '''
    def __init__(self, keyid=None, key=None, region="us-west-1"):
        self._sut_path = os.path.join(os.path.dirname(__file__),
                                      '..', 'sut', 'login.py')
        self._status = ''
        self.keyid = keyid
        self.key = key
        if(keyid is None or key is None):
            aws_cred = get_aws_credential()
            self.keyid = aws_cred['keyid']
            self.key = aws_cred['key']
        self.region = region
        self.sess = Session(region_name = self.region,
            aws_access_key_id = self.keyid,
            aws_secret_access_key = self.key)
        self.ec2 = self.sess.resource('ec2')
        self.client = self.ec2.meta.client
        self.eips = {} # elastic IPs
        self.pubips = []
        for addr in self.client.describe_addresses()['Addresses']:
            pubIP = addr['PublicIp']
            self.pubips.append(pubIP)
            assoId = None
            if 'AssociationId' in addr:
                assoId = addr['AssociationId']
            self.eips[pubIP] = assoId
        self.pubips = sort_ip(self.pubips)
        self.kps = {} # Key Pairs Dict with KeyName
        for kp in self.client.describe_key_pairs()['KeyPairs']:
            self.kps[kp['KeyName']] = kp['KeyFingerprint']
            
    def vpcid_by_name(self, name):
        '''Return VPC ID for the VPC with a given name'''
        vpcid = None
        for vpc in self.client.describe_vpcs()['Vpcs']:
            vpcId = vpc['VpcId']
            if 'Tags' in vpc:
                for tag in vpc['Tags']:
                    if tag['Key'] == 'Name' and tag['Value'] == name:
                        ntlog("VPC %s has an id of %s" % (name, vpcId))
                        vpcid = vpcId
        if vpcid is None :
            ntlog("VPC %s does not exists" % name)
        return vpcid

    def vpcname_by_id(self, vpcid):
        '''Return name the VPC given the VPC ID'''
        name = None
        for vpc in self.client.describe_vpcs(VpcIds = [vpcid])['Vpcs']:
            if 'Tags' in vpc:
                for tag in vpc['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
        if name is None:
            ntlog("VPC ID %s does not have a name specified" % vpcid)
        return name

    def get_eips_vpc(self, name):
        '''Get a list of EIPs and their association'''
        eips = []
        vpc_id = self.vpcid_by_name(name)
        for eip in self.eips:
            addr = self.client.describe_addresses(PublicIps=[eip])
            resp = addr['Addresses'][0]
            if 'NetworkInterfaceId' in resp:
                nif = self.ec2.NetworkInterface(resp['NetworkInterfaceId'])
                if nif.vpc_id == vpc_id:
                    eips.append(eip)
        return eips
            
    def disassociate_eips(self, vpc_name = None):
        '''Disassociate an EIP in order for cleanup'''
        eips = self.eips
        if vpc_name is not None:
            eips = self.get_eips_vpc(name = vpc_name)
        for eip in eips:
            if self.eips[eip] is not None:
                self.client.disassociate_address(AssociationId=self.eips[eip])

    def set_vpc_peering(self, vpc_name, vpc_peer_name):
        '''Set a new VPC peering, assume the same id owns both requester
        and accepter'''
        vpc_id = [self.vpcid_by_name(vpc_name), 
            self.vpcid_by_name(vpc_peer_name)]
        peering = self.client.create_vpc_peering_connection(
            VpcId = vpc_id[0], PeerVpcId = vpc_id[1])['VpcPeeringConnection']
        peer= self.client.accept_vpc_peering_connection(
            VpcPeeringConnectionId = 
            peering['VpcPeeringConnectionId'])['VpcPeeringConnection']
        ntlog("Peering state between %s and %s is %s. Message: %s" % 
            (vpc_name, vpc_peer_name, 
            peer['Status']['Code'], peer['Status']['Message']))
        lbl =  ['Requester', 'Accepter']
        for idx in range(2):
            local = lbl[idx] + 'VpcInfo'
            remote = lbl[1-idx] + 'VpcInfo'
            vpc = Ec2Vpc(aec2 = self, vpcid = peer[local]['VpcId'])
            rtt = vpc.get_route_table_main()
            vpc.add_route(rtt=rtt, cidr=peer[remote]['CidrBlock'],
                gw_type = 'VpcPeeringConnection',
                gw_id = peer['VpcPeeringConnectionId'])
            #rtt.create_route(DestinationCidrBlock=peer[remote]['CidrBlock'],
            #    VpcPeeringConnectionId = peer['VpcPeeringConnectionId'])
        ntlog("Routes added between %s and %s" %(vpc_name, vpc_peer_name))

    def get_vpc_peering(self, vpc_id=None, vpc_name=None):
        '''Get a list of VPC Peering Connections'''
        if vpc_id is None and vpc_name is None:
            ntlog("either vpc_id or vpc_name is required", logging.ERROR)
            return None
        if vpc_id is None:
            vpc_id = self.vpcid_by_name(vpc_name)
        vpc_pids_requester = self.client.describe_vpc_peering_connections(
            Filters = [ {'Name': 'requester-vpc-info.vpc-id',
                        'Values': [vpc_id]}]
                        )['VpcPeeringConnections']
        vpc_pids_accepter = self.client.describe_vpc_peering_connections(
            Filters = [ { 'Name':   'accepter-vpc-info.vpc-id',
                        'Values':   [vpc_id]}]
                        )['VpcPeeringConnections']

        vpc_peer_ids = []
        for peer in (vpc_pids_requester + vpc_pids_accepter):
            vpc_peer_ids.append(peer['VpcPeeringConnectionId'])
        return vpc_peer_ids

    def del_vpc_peering(self, vpc_peer_ids):
        '''Delete VPC Peering for the Peer IDs, it can be a single
        ID string or a list of ID strings'''
        if type(vpc_peer_ids) is not list:
            vpc_peer_ids = [vpc_peer_ids]
        status = True
        for peerid in vpc_peer_ids:
            peer = self.ec2.VpcPeeringConnection(peerid)
            st = peer.delete()
            if not st:
                ntlog("Deleting VPC Peering with ID %s failed" % peerid, 
                    logging.WARN)
                status = False
            else:
                ntlog("VPC Peering with ID %s was deleted" % peerid)
        return status

    def get_netif_id(self, evpc, pvt):
        '''
        Return NetworkInterfaceId for the interface, with which the private 
        IP address is associated in Ec2Vpc evpc
        '''
        resp = self.client.describe_network_interfaces(
            Filters=[{  'Name': "addresses.private-ip-address",
                        'Values': [pvt]},
                     {  'Name': "vpc-id",
                        'Values': [evpc.vpcid]},
                        ],
                    )
        return resp['NetworkInterfaces'][0]['NetworkInterfaceId']

    def associate_eip(self, evpc, pub, pvt):
        '''Associate an EIP to a private address'''
        # Keeps asking for PublicIps instead of PublicIp
        #allocation_id = evpc.ec2.ClassicAddress(pub).allocation_id
        allocation_id = evpc.get_address_allocation_id(pub)
        if pvt in evpc.enis:
            nifid = evpc.enis[pvt].network_interface_id
        else:
            nifid = self.get_netif_id(evpc, pvt)
        assoc = evpc.client.associate_address(
            NetworkInterfaceId = nifid,
            PrivateIpAddress=pvt, AllocationId = allocation_id)
        self.eips[pub] = assoc['AssociationId']

    def _run_command(self, command, *args):
        command = [sys.executable, self._sut_path, command] + list(args)
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        self._status = process.communicate()[0].strip()

class IPerf:
    '''
    Iperf network throughput test with two ways to initialize
        - NT instance of the server and client
        - IP/host names of the server and client, as well as credentials
    '''
    def __init__(self, server, client, user=None, password=None, key=None,
        suser = None, spassword = None, skey=None,
        cuser = None, cpassword = None, ckey=None,
        udp=False, sport=80, cport=None, duration=30, interval=None,
        soption=None, coption=None, mss=1448):
        if type(server) is NT :
            self.hs = server
        else:
            self.server = server
            self.saddr = server
        if type(client) is NT :
            self.hc = client
        else:
            self.client = client
            self.caddr = client
        self.sport = sport
        self.cport = cport
        self.udp   = udp
        self.duration = duration
        if interval is None :
            self.interval = duration
        self.soption = soption
        self.coption = coption
        self.mss = mss
        self.daemon = True
        if suser is None :
            self.suser = user
        else :
            self.suser = suser
        if cuser is None :
            self.cuser = user
        else :
            self.cuser = cuser
        if spassword is None :
            self.spassword = password
        else :
            self.spassword = spassword
        if cpassword is None :
            self.cpassword = password
        else :
            self.cpassword = cpassword
        if skey is None :
            self.skey = key
        else :
            self.skey = skey
        if ckey is None :
            self.ckey = key
        else :
            self.ckey = ckey
        self.conn_proto = "ssh"
        self.os = "linux"

    def connect(self):
        '''Connect to both client and server'''
        self.hs = NT(host = self.server, conn_proto = self.conn_proto,
            os = self.os, ssh_key = self.skey, user = self.suser)
        self.hc = NT(host = self.client, conn_proto = self.conn_proto,
            os = self.os, ssh_key = self.ckey, user = self.cuser)


    def config(self, saddr, caddr, sport=None, udp=None,
        sgateway=None, cgateway=None, mask=VPC_SUBNET_MASK, duration=None):
        '''Configure route table and specify iperf params'''
        smask = mask
        if "/" in saddr:
            smask = get_mask(saddr)
            saddr = strip_mask(saddr)
        cmask = mask
        if "/" in caddr:
            cmask = get_mask(caddr)
            caddr = strip_mask(caddr)

        self.saddr = saddr
        self.caddr = caddr

        if sport is not None:
            self.sport = sport
        if udp is not None:
            self.udp = udp
        #self.hs.cmd("sudo ifconfig eth1 up " + saddr + "/" + str(smask))
        if sgateway is not None:
            while caddr in self.hs.cmd("route -n") :
                self.hs.cmd("sudo route del -host " + caddr)
            self.hs.cmd("sudo route add -host " + caddr + " gw " + sgateway)
        #self.hc.cmd("sudo ifconfig eth1 up " + caddr + "/" + str(cmask))
        if cgateway is not None:
            while saddr in self.hc.cmd("route -n") :
                self.hc.cmd("sudo route del -host " + saddr)
            self.hc.cmd("sudo route add -host " + saddr + " gw " + cgateway)
        #return (caddr in self.hs.cmd("route -n")) and \
        #    (saddr in self.hc.cmd("route -n"))
        if duration is not None:
            self.duration = duration

    def start_server(self, daemon = True):
        '''Start server in daemon mode or not'''
        svr_mode = "-s"
        if daemon :
            svr_mode += "D"
        cmd_svr = "sudo iperf3 " + svr_mode + " -p " + str(self.sport) 
        for h in (self.hs, self.hc) :
            h.cmd(cmd_svr)

    def summary(self, result):
        pass

    def chk_connect(self, timeout=60):
        result = False
        return self.hs.ping(dest = self.caddr, timeout = timeout)

    def get_bandwidth(self, duration = None, udp=None, enable_json=True,
        mss=None):
        if mss is None:
            mss = self.mss
        '''Get the bandwidth using Iperf3'''
        if duration is None:
            duration = self.duration
        if udp is None:
            udp = self.udp
        results = []
        params = [  {"handle": self.hs, "client": self.caddr},
                    {"handle": self.hc, "client": self.saddr},
                 ]
        for param in params:                 
            cmd = "sudo iperf3 -c " + param["client"] + " -i " + \
                str(self.interval) + " -t " + str(duration) + \
                " -p " + str(self.sport)
            if(enable_json):
                cmd += " -J"
            if udp :
                cmd += " -u -b 10000m"
                re_pattern = "Lost/Total Datagrams.+sec\s+([\d\.]+)\s+" + \
                    "(\S+)\s+([\d\.]+)\s+(\S+)\s+([\d\.]+)\s+(\S+)" + \
                    "\s+(\d+)/(\d+)\s+\((\d+)%\)"
                fields = ['bytes_sent', 'bytes_sent_unit', 'bw_send', 
                    'bw_send_unit', 'jitter', 'jitter_unit', 'frames_lost', 
                    'frames_sent', 'loss_percent']
                jfields = {
                    'timestamp':    'start.timestamp.timesecs',
                    'protocol':     'start.test_start.protocol',
                    'size':         'start.test_start.blksize',
                    'local_host':   'start.connected.0.local_host',
                    'remote_host':  'start.connected.0.remote_host',
                    'duration':     'start.test_start.duration',
                    'seconds':      'end.sum.seconds',
                    'bytes_tx':     'end.sum.bytes',
                    'bps_tx':       'end.sum.bits_per_second',
                    'pkt_loss':     'end.sum.lost_packets',
                    'packets':      'end.sum.packets',
                    'jitter_ms':    'end.sum.jitter_ms',
                    'loss_pct':     'end.sum.lost_percent',
                }
            else :
                cmd += " -V -M %d" % mss
                re_pattern = "Summary Results:.+" + \
                    "sec\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+sender" + \
                    ".+sec\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+receiver"
                fields = ['bytes_sent', 'bytes_sent_unit', 'bw_send', 
                    'bw_send_unit', 'tcp_retries', 'bytes_rcvd',
                    'bytes_rcvd_unit', 'bw_recv', 'bw_recv_unit']
                jfields = {
                    'timestamp':    'start.timestamp.timesecs',
                    'protocol':     'start.test_start.protocol',
                    'size':         'start.tcp_mss',
                    'local_host':   'start.connected.0.local_host',
                    'remote_host':  'start.connected.0.remote_host',
                    'duration':     'start.test_start.duration',
                    'seconds':      'end.sum_sent.seconds',
                    'bytes_tx':     'end.sum_sent.bytes',
                    'bytes_rx':     'end.sum_received.bytes',
                    'bps_tx':       'end.sum_sent.bits_per_second',
                    'bps_rx':       'end.sum_received.bits_per_second',
                    'pkt_loss':     'end.sum_sent.retransmits',
                }

            ntlog("Starting iperf3 testing for %s seconds" % duration)
            output = param["handle"].cmd(cmd=cmd, timeout = duration + 10)
            ntlog("iperf3 testing completed")
            result = {}
            if enable_json:
                jout = json.loads(output)
                for field in jfields:
                    result[field] = get_dict_leaf(jout, jfields[field], '.')
            else:
                m = re.search(re_pattern, output, re.DOTALL)
                if m:
                    for fieldId in range(0, len(fields)):
                        result[fields[fieldId]] = m.group(fieldId + 1)
                else :
                    ntlog("Unable to parse the following results, " + \
                        "bandwidth test failed %s" % output)
            results.append(result)
        return results

###### main function as a standalone script

if __name__ == "__main__":
    pass

