from nt import *
import VmxAws
import json,csv
def vmx_perf():
    va = VmxAws.VmxAws('xwuw01')
    result = []
    lnx01 = 'xwu-lnx23'
    lnx02 = 'xwu-lnx24'
    #gwoffset = [[9, 10]] #, [15, 16], [21, 22]]
    gwoffset = [[13, 14], [19, 20]]
    for gw in gwoffset :
        result.extend(va.perf_report(lnx01, lnx02, gw_offset=gw))
    
    with open('result.json', 'w') as fp:
        json.dump(result, fp)
    #with open('result.json', 'r') as fp:
    #    result = json.load(fp)
    #f = csv.writer(open("result.csv", "wb+"))
    with open('result.csv', 'w') as f:
        w = csv.DictWriter(f, result[20].keys())
        w.writeheader()
        for row in result:
            w.writerow(row)

vmx_perf()

import xml.etree.ElementTree as ET
def xmlpath():
    xout = '<l2ng-l2ald-iff-interface-information> <l2ng-l2ald-iff-interface-entry style="brief"> <l2iff-interface-lr-name/> <l2iff-interface-rtt-name>default-switch</l2iff-interface-rtt-name> <l2ng-l2ald-iff-interface-entry style="brief"> <l2iff-interface-name>xe-0/0/32.0</l2iff-interface-name> <l2iff-interface-vlan-name/> <l2iff-interface-mac-limit>65535</l2iff-interface-mac-limit> <l2iff-interface-vlan-member-stp-state/> <l2iff-interface-flags/> <l2iff-interface-vlan-member-tagness>untagged</l2iff-interface-vlan-member-tagness> </l2ng-l2ald-iff-interface-entry> <l2ng-l2ald-iff-interface-entry style="brief"> <l2iff-interface-vlan-name>VLAN100</l2iff-interface-vlan-name> <l2iff-interface-vlan-id>100</l2iff-interface-vlan-id> <l2iff-interface-vlan-member-tagness>untagged</l2iff-interface-vlan-member-tagness> <l2iff-interface-mac-limit>65535</l2iff-interface-mac-limit> <l2iff-interface-vlan-member-stp-state>Forwarding</l2iff-interface-vlan-member-stp-state> <l2iff-interface-flags/> </l2ng-l2ald-iff-interface-entry> </l2ng-l2ald-iff-interface-entry> </l2ng-l2ald-iff-interface-information>'
    xml = xmlpath(ET.fromstring(xout))
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


