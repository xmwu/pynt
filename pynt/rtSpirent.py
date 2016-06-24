'''
Common tasks using Spirent TestCenter for network testing
'''
import os
import sys
import time
import datetime
import re
from nt import *
from StcPython import StcPython

class rtSpirent(StcPython):
    '''
    Main class manage all Spirent TestCenter (STC) related tasks, including
        - Chassis Management
        - Port Management
        - Protocol Emulation
        - Traffic Simulation
        - Statistics Collection and Analysis

    It doesn't require ports to be reserved if just for chassis information
    '''

###### Constructor
    def __init__(self):
        '''
        Constructor for initialization
        '''
        # rtSpirent requires 32 bit Python
        if (sys.maxsize != 0x7fffffff) :
            print "Spirent API requires 32 bit Python executable"

        ts = datetime.datetime.utcnow()
        print "%s Initializing rtSpirent instance, be patient" % ts
        #super(rtSpirent, self).__init__(self)
        StcPython.__init__(self)
        self.proj = None
        self.chas = []
        self.g = {'proj' : None, 'hPort' : None}
        te = datetime.datetime.utcnow()
        duration = te - ts
        print "%s rtSpirent initialized after %s " % (te, duration)

    def initModules(self, **kargs):
        '''
        Initialize modules by taking a list of port in format of 
        chassis_address/slot/port, the goal is to similate RT API
        init_modules, coding style removes _ in method variable name
        '''
        port = kargs['port']
        proj = self.create('project')
        self.g['proj'] = proj
        hPort = []
        locPort = []
        chas = {}

        for p in port:
            pt = p['port'].split("/")
            chas[pt[0]] = 1
            loc = "//%s" % p['port']
            hPort.append(self.create('port', under=proj, location=loc))
    
        self.perform('attachPorts', portList=hPort, autoConnect='TRUE')
        self.apply()
        self.g['hPort'] = hPort
        self.chas = chas.keys()

    def cleanup(self):
        print 'Cleaning up Sirent TestCenter ...'
        for chas in self.chas:
            self.disconnect(chas)

        self.delete(self.g['proj'])

######## Sample from prog guide ############
    def traffPrep(self, **kargs):
        '''
        Prepare traffic setup by create streamblock, generator and analyzer
        '''
        print 'Creating StreamBlock on Port 1'
        streamBlock = self.create('streamBlock', under=port1 )
        generator = self.get(port1, 'children-generator')
        analyzer = self.get(port2, 'children-Analyzer')

    def resultSub(self):
        print 'Call Subscribe...'
        port1GeneratorResult = stc.subscribe(Parent=project,
            ResultParent=port1,
            ConfigType='Generator',
            resulttype='GeneratorPortResults',
            filenameprefix="Generator_port1_counter_%s" % port1,
            Interval=2 )
        port2AnalyzerResult = stc.subscribe(Parent=project,
            ResultParent=port2,
            ConfigType='Analyzer',
            resulttype='AnalyzerPortResults',
            filenameprefix="Analyzer_port2_counter_%s" % port2,
            Interval = 2)

    def trafficOp(self):
        print 'Starting Traffic...'
        stc.perform('AnalyzerStart', analyzerList=analyzer)
        print 'start', analyzer
        # wait for analyzer to start
        stc.sleep(1)
        stc.perform('GeneratorStart', generatorList=generator)
        print "start", generator
        # generate traffic for 5 seconds
        print 'Sleep 5 seconds...'
        stc.sleep(5)
        print 'Stopping Traffic...'
        stc.perform('GeneratorStop', generatorList=generator)
        stc.perform('AnalyzerStop', analyzerList=analyzer)
        print 'stop', generator
        print 'stop', analyzer
        print 'Call Unsubscribe...'
        stc.unsubscribe(port2AnalyzerResult)
        stc.unsubscribe(port1GeneratorResult)

######## Sample from prog guide END ############

###### quick handy tools
    def version(self):
        '''
        Display chassis FirmwareVersion
        '''
        if not self.chas :
            ntlog("Use stc.connect(\"stc01\" [, \"stc02\"]) first")
            sys.exit(1)
        else :
            for hChas in(self.chas) :
                info = self.get(hChas)
                print "Spirent Chassis %s: Version %s SN %s PN %s" % (
                    info['Hostname'], info['FirmwareVersion'],
                        info['SerialNum'], info['PartNum'])

    def inventory(self):
        '''
        List all test modules, models and serial number
        '''
        if not self.chas :
            ntlog("Use stc.connect(\"stc01\" [, \"stc02\"]) first")
            sys.exit(1)
        else:
            for hChas in(self.chas):
                info = self.get(hChas, "children-PhysicalTestModule").split(" ")
                for module in(info):
                    info_mod = self.get(module)
                    if(info_mod['Status'] == 'MODULE_STATUS_UP') :
                        print "Module%s: Ports: %s Model: %s Desc: %s SN: %s" % (
                            info_mod['Index'], info_mod['PortCount'], 
                            info_mod['Model'], info_mod['Description'],
                            info_mod['SerialNum'])

    def license(self):
        '''
        List licensed features for a given chassis
        '''
        if not self.chas :
            ntlog("use stc.connect(\"stc01\" [,\"stc02\"]) first")
            sys.exit(1)
        else:
            print "Getting licenses installed for connected chassis..."
            print "License Description      Version   Expiration"
            licresponse=self.perform("LicenseShow", ChassisList=self.chas)
            for licentry in(licresponse['LicenseEntryList'][1:-1].split("} {")):
                lic = licentry.split(";")
                if re.search("^(permanent|2015)", lic[3]):
                    print "%s\t%s\t%s" % (lic[0], lic[2], lic[3])
                    

###### Override parent methods
    def connect(self, *hosts):
        '''
        Wrapper of native connect methods, but stores chassis handles
        '''
        super(rtSpirent, self).connect(*hosts)
        if not self.chas:
            self.chas = self.get("system1.PhysicalChassisManager", 
                "children-PhysicalChassis").split(" ")
        else:
            self.chas = list(set(self.chas.extend(
                self.get("system1.PhysicalChassisManager",
                    "children-PhysicalChassis").split(" "))))
        


if __name__ == "__main__":
    '''
    Testcases to validate
    '''
    stc = rtSpirent()
    #print "Now trying to connect to and display Spirent chassis inventory"
    #stc.connect("perf-stc2", "app-stc2", "app-stc3")
    #stc.connect("perf-stc2")
    #stc.connect("perf-stc2", "tt-xwu-1785268-vm")
    #stc.connect("rbu-spirent01", "vcpe-stc01")
    stc.connect("vcpe-stc01")
    stc.version()
    #stc.license()
    stc.inventory()
    #ports = [{'port' : 'perf-stc2/5/7', 'media' : 'fiber'},
    #        {'port' : 'perf-stc2/7/6', 'media' : 'fiber'},]
    #ports = [{'port' : 'perf-stc2/6/7', 'media' : 'fiber'},
    #        {'port' : 'perf-stc2/7/5', 'media' : 'fiber'},]
    #ports = [{'port' : 'tt-xwu-1785268-vm/1/1'},
    #        {'port' : 'tt-xwu-1785268-vm/1/2'},]
    #stc.initModules(port = ports)
    raw_input("Press Enter to continue...")


