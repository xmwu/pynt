from nt import *
import VmxAws
import json,csv
def vmx_perf():
    va = VmxAws.VmxAws('reg-vmx')
    result = []
    lnx01 = 'reg-lnx01'
    lnx02 = 'reg-lnx02'
    #gwoffset = [[9, 10]] #, [15, 16], [21, 22]]
    #gwoffset = [[5, 6], [7, 8], [9, 10], [11, 12], [13, 14], [15, 16], [17, 18], [19, 20], [21, 22]]
    #gwoffset = [[3, 4], [5, 6], [7, 8], [9, 10], [11, 12], [13, 14], [15, 16], [17, 18], [19, 20]]
    #gwoffset = [[13, 14], [15, 16], [19, 20], [21, 22]]
    #gwoffset = [[7, 8], [9, 10], [13, 14], [15, 16]]
    #gwoffset = [[17, 18], [19, 20], [21, 22]]
    #gwoffset = [[5, 6], [7, 8], [9, 10]]
    gwoffset = [[13, 14]]
    for gw in gwoffset :
        result.extend(va.perf_report(lnx01, lnx02, gw_offset=gw, ipsecalg=[],
            conn=["no_vmx", "direct", "bgp-ospf-gre"]))
    
    with open('result.json', 'w') as fp:
        json.dump(result, fp)
    #with open('result.json', 'r') as fp:
    #    result = json.load(fp)
    #f = csv.writer(open("result.csv", "wb+"))
    with open('result.csv', 'w') as f:
        w = csv.DictWriter(f, result[2].keys())
        w.writeheader()
        for row in result:
            w.writerow(row)

vmx_perf()

def chk(host, port, prompt=None):
    chk_host_port(host=host, port=port, prompt=prompt)

#chk("192.168.128.135", 22, "SSH")
#chk("localhost", 80, "SSH")

import xml.etree.ElementTree as ET
def xmlpath():
    xout = '<l2ng-l2ald-iff-interface-information> <l2ng-l2ald-iff-interface-entry style="brief"> <l2iff-interface-lr-name/> <l2iff-interface-rtt-name>default-switch</l2iff-interface-rtt-name> <l2ng-l2ald-iff-interface-entry style="brief"> <l2iff-interface-name>xe-0/0/32.0</l2iff-interface-name> <l2iff-interface-vlan-name/> <l2iff-interface-mac-limit>65535</l2iff-interface-mac-limit> <l2iff-interface-vlan-member-stp-state/> <l2iff-interface-flags/> <l2iff-interface-vlan-member-tagness>untagged</l2iff-interface-vlan-member-tagness> </l2ng-l2ald-iff-interface-entry> <l2ng-l2ald-iff-interface-entry style="brief"> <l2iff-interface-vlan-name>VLAN100</l2iff-interface-vlan-name> <l2iff-interface-vlan-id>100</l2iff-interface-vlan-id> <l2iff-interface-vlan-member-tagness>untagged</l2iff-interface-vlan-member-tagness> <l2iff-interface-mac-limit>65535</l2iff-interface-mac-limit> <l2iff-interface-vlan-member-stp-state>Forwarding</l2iff-interface-vlan-member-stp-state> <l2iff-interface-flags/> </l2ng-l2ald-iff-interface-entry> </l2ng-l2ald-iff-interface-entry> </l2ng-l2ald-iff-interface-information>'
    xml = ET.fromstring(xout)
    v = ''
    tags = {
        'ifname':   'l2iff-interface-name',
        'vlan':     'l2iff-interface-vlan-name',
        'tagness':  'l2iff-interface-vlan-member-tagness',
    }
    for entry in xml.findall('.//l2ng-l2ald-iff-interface-entry/l2ng-l2ald-iff-interface-entry'):
        for tag, xtag in tags.iteritems():
            value = entry.find(xtag)
            v += tag + ": "
            if value is None or value.text is None:
                v += 'None'
            else:
                v += value.text
            v += "\t"
        v += "\n"
    print(v)

def xpath2():
    xout='''<rpc-reply xmlns:junos="http://xml.juniper.net/junos/16.1D0/junos">
    <route-information xmlns="http://xml.juniper.net/junos/16.1D0/junos-routing">
        <!-- keepalive -->
        <route-table>
            <table-name>bgp.evpn.0</table-name>
            <destination-count>3</destination-count>
            <total-route-count>3</total-route-count>
            <active-route-count>3</active-route-count>
            <holddown-route-count>0</holddown-route-count>
            <hidden-route-count>0</hidden-route-count>
            <rt junos:style="brief">
                <rt-destination>1:10.254.255.1:0::0::FFFF:FFFF</rt-destination>
                <rt-prefix-length junos:emit="emit">304 AD/ESI</rt-prefix-length>
                <rt-entry>
                    <active-tag>*</active-tag>
                    <current-active/>
                    <last-active/>
                    <protocol-name>BGP</protocol-name>
                    <preference>170</preference>
                    <age junos:seconds="6242">01:44:02</age>
                    <local-preference>100</local-preference>
                    <learned-from>10.254.255.2</learned-from>
                    <as-path>I
                    </as-path>
                    <validation-state>unverified</validation-state>
                    <nh>
                        <selected-next-hop/>
                        <to>10.128.0.1</to>
                        <via>ae0.0</via>
                    </nh>
                </rt-entry>
            </rt>
            <rt junos:style="brief">
                <rt-destination>1:10.254.255.3:0::0::FFFF:FFFF</rt-destination>
                <rt-prefix-length junos:emit="emit">304 AD/ESI</rt-prefix-length>
                <rt-entry>
                    <active-tag>*</active-tag>
                    <current-active/>
                    <last-active/>
                    <protocol-name>BGP</protocol-name>
                    <preference>170</preference>
                    <age junos:seconds="6286">01:44:46</age>
                    <local-preference>100</local-preference>
                    <learned-from>10.254.255.2</learned-from>
                    <as-path>I
                    </as-path>
                    <validation-state>unverified</validation-state>
                    <nh>
                        <selected-next-hop/>
                        <to>10.128.0.5</to>
                        <via>xe-1/0/0.0</via>
                        <mpls-label>Push 401952</mpls-label>
                    </nh>
                </rt-entry>
            </rt>
            <rt junos:style="brief">
                <rt-destination>3:10.254.255.3:2345::2345::10.254.255.3</rt-destination>
                <rt-prefix-length junos:emit="emit">304 IM</rt-prefix-length>
                <rt-entry>
                    <active-tag>*</active-tag>
                    <current-active/>
                    <last-active/>
                    <protocol-name>BGP</protocol-name>
                    <preference>170</preference>
                    <age junos:seconds="6282">01:44:42</age>
                    <local-preference>100</local-preference>
                    <learned-from>10.254.255.2</learned-from>
                    <as-path>I
                    </as-path>
                    <validation-state>unverified</validation-state>
                    <nh>
                        <selected-next-hop/>
                        <to>10.128.0.5</to>
                        <via>xe-1/0/0.0</via>
                        <mpls-label>Push 401952</mpls-label>
                    </nh>
                </rt-entry>
            </rt>
        </route-table>
    </route-information>
    <cli>
        <banner></banner>
    </cli>
</rpc-reply>'''
    xout = re.sub(' xmlns="[^"]+"', '', xout)
    xml = ET.fromstring(xout)
    v = ''
    for entry in xml.findall('.//rt[rt-prefix-length="304 AD/ESI"][rt-destination="1:10.254.255.3:0::0::FFFF:FFFF"]/rt-entry'):
        print "OK"
        v = entry.find('protocol-name')
    print(v)

