*** Settings ***
Library	../../pynt/VmxAws.py	vpc=w01	cidr=192.168.128.0/17	subnet_mask=24	subnet_cnt=6

*** Variables ***
${vpc_name}	w01
${key_file}	~/.ssh/seanvmx.pem
${ami_vmx}	ami-05daa465
${ami_lnx}	ami-06116566
${inst_type_vmx}	m4.xlarge
${inst_type_lnx}	c4.8xlarge
${intf_per_subnet}	${30}
${vmx_if_cnt}	${3}
${vmx_subnet_cnt}	${5}
${key_name}	seanvmx
${lic}	E418396532.lic:Lic20G.txt

*** Test Cases ***
#VPC Cleanup
#	[Documentation]	Remove VPC ${vpc_name} and its related resouces
#	[Tags]	VPC
#	Vpc Cleanup

Create Subnets
	[Documentation]	Create Subnets
	[Tags]	VPC
	Vpc Create Subnet	${vmx_subnet_cnt}

Create Security Groups
	[Documentation]	Two security groups to allow external from JNPR and Internal VPC
	[Tags]	VPC
	Vpc Create Security Groups

Create Elastic Network Interfaces ENIs
	[Documentation]	Create ${intf_per_subnet} ENIs per Subnet with predefined static Private IPs
	[Tags]	VPC
	Vpc Create Interface	${intf_per_subnet}

Create Internet Gateway
	[Documentation]	Create Internet Gateway and attach to VPC
	[Tags]	VPC
	Vpc Create Internet Gateway

Create Route Tables
	[Documentation]	Create route tables for the VPC if needed, the number includes the main route table that is auto generated during VPC creation
	[Tags]	VPC
	Vpc Create Route Table	${3}

#Launch VMX Instances
#	[Documentation]	Create VMX instance with ${vmx_if_cnt} interfaces
#	[Tags]	VMX
#	${inst1}	Create Dictionary	iname=vmx01	offset=${0}	itype=m4.xlarge
#	${inst2}	Create Dictionary	iname=vmx02	offset=${3}	itype=m4.2xlarge
#	${inst3}	Create Dictionary	iname=vmx03	offset=${4}	itype=c3.2xlarge
#	${inst4}	Create Dictionary	iname=vmx04	offset=${5}	itype=c4.2xlarge
#	${inst4}	Create Dictionary	iname=vmx05	offset=${6}	itype=c4.8xlarge
#	#@{vmx_params}	Create List	${inst1}	${inst2}	${inst3}	${inst4}	&{inst5}
#	@{vmx_params}	Create List	${inst1}	${inst2}
#	Launch Instances	inst_params=@{vmx_params}	ami=${ami_vmx}	key_name=${key_name}	inst_type=${inst_type_vmx}	ifcount=${vmx_if_cnt}

#Associate Public IP Address to Instance Private IP
#	[Documentation]	Map AWS Elastic Public IP to One Elastic Network Interface
#	[Tags]	VMX
#	Eip Associate	${0}	192.168.128.4
#	Eip Associate	${3}	192.168.128.251

#Start VMX Instance
#	[Documentation]	Start VMX and measure bringup time
#	[Tags]	VMX
#	@{inst_names}	Create List	vmx01	lnx01	lnx02
#	: For	${inst_name}	in	@{inst_names}
#	\	Start Instance	${inst_name}

Launch Endpoint EC2 Ubuntu Hosts
	[Documentation]	Launch Ubuntu
	[Tags]	VPC
	@{ifset1}	Create List	0.1	1.1	2.1	3.1	4.1
	@{ifset2}	Create List	0.2	1.2	2.2	3.2	4.2
	${lnx1}	Create Dictionary	iname=lnx01	ips=@{ifset1}
	${lnx2}	Create Dictionary	iname=lnx02	ips=@{ifset2}
	@{params}	Create List	${lnx1}	${lnx2}
	Launch Instances	inst_params=@{params}	ami=${ami_lnx}	key_name=${key_name}	inst_type=${inst_type_lnx}
	EIP Associate	${1}	192.168.128.5
	EIP Associate	${2}	192.168.128.6

#Stop VMX Instance
#	[Documentation]	Stop VMX and measure hybernate time
#	[Tags]	VMX
#	#@{inst_names}	Create List	lnx01	lnx02	vmx01
#	@{inst_names}	Create List	lnx01	lnx02	vmx01
#	: For	${inst_name}	in	@{inst_names}
#	\	Stop Instance	${inst_name}
#
#Terminate VMX Instance
#	[Documentation]	Terminate VMX and measure hybernate time
#	[Tags]	VMX
#	@{inst_names}	Create List	lnx01	lnx02
#	: For	${inst_name}	in	@{inst_names}
#	\	Terminate Instance	${inst_name}

Setup iperf3 on Linux hosts
	[Documentation]	Install necessary packages and iperf3 from github
	[Tags]	Performance
	@{inst_names}	Create List	lnx01	lnx02
	: For	${inst_name}	in	@{inst_names}
	\	Install iperf3	${inst_name}

VMX Basic Setup
	[Documentation]	Configure root password, interface addresses and load licenses
	[Tags]	VMX
	@{vmx}	Create List	vmx09	vmx10
	: For	${v}	in	@{vmx}
	\	VMX Basic Setup	name=${v}	licenses=${lic}


Enable SR-IOV
	[Documentation]	Enable enhanced networking with SR-IOV support
	[Tags]	Performance
	@{hosts}	Create List	vmx09	vmx10
	: For	${host}	in	@{hosts}
	\	Stop Instance	${host}
	\	Enable SRIOV	${host}
	\	Start Instance	${host}
	\	Chk SRIOV	${host}

#Measure Performance using IPerf3
#	[Documentation]	Configure proper interface and routes on hosts, and start test
#	[Tags]	Performance
#	#@{lnx01}	Create List	lnx01	192.168.1.5	192.168.1.4
#	#@{lnx02}	Create List	lnx02	192.168.2.6	192.168.2.4
#	Throughput with IPerf3	lnx01	lnx02

#Check VPC Environment
#	Vpc Snapshot	${vpc_name}

*** Keywords ***
	
