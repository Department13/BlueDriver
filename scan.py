import bluetooth.ble
import json
import time
import pdb
import argparse
from gattlib import GATTRequester
from gattlib import DiscoveryService

# Thanks to Bluepy project for this table and the simple to-string method
propNames = {0b00000001 : "BROADCAST",
             0b00000010 : "READ",
             0b00000100 : "WRITE NO RESPONSE",
             0b00001000 : "WRITE",
             0b00010000 : "NOTIFY",
             0b00100000 : "INDICATE",
             0b01000000 : "WRITE SIGNED",
             0b10000000 : "EXTENDED PROPERTIES",
}


def connect(deviceaddr):
    """
    Attempt a connection to the target device - notoriously unreliable due to driver issues and the ephemeral nature of BTLE
    """

    deviceHandle = GATTRequester(deviceaddr, False, args.listen_interface)
    flag = 0
    device = None

    while flag<5:
        try:
            #bool wait,std::string channel_type, std::string security_level, int psm, int mtu)
            deviceHandle.connect(True, 'public','low')
            break
        except Exception,e:
            print e
            flag += 1
    return deviceHandle
        
    #device = GATTRequester(device)
    #d = None
    #while d is None:
    #    try:
    #        GATTRequester(deviceaddr, False, args.talk_interface)
    #    except RuntimeError,e :
    #        time.sleep(5)
    #        print e
    #        continue
    #return GATTRequester(deviceaddr)

    #d = None
    #numtimes = 0
    #while numtimes < 5:
    #    try:
    #        d = GATTRequester(deviceaddr, False, args.talk_interface)
    #        if d is not None:
    #            d.connect()
    #            derp =d 
    #            pdb.set_trace()
    #            print "\tconnected"
    #            return d
    #    except Exception, e:
    #        print e
    #        print "\tRetry connection"
    #        time.sleep(1)
    #        numtimes += 1
    #if d == None:
    #    print "\tcouldn't connect"
    #return d

def enumerate(address):
    """
    Attempts to discover all characteristics and dump all values from the device
    device( services( charactaristics( values )))
    """
    #device = GATTRequester(device)
    device = connect(address)
    #if device == None:
    #    time.sleep(1)
    #    return
    #time.sleep(1)
    try:
        chars = device.discover_characteristics()
        print "\t Device characteristics:" + str(chars)
    except Exception,e:
        try:
            print e
            device = connect(address)
            chars = device.discover_characteristics()
        except Exception,e:
            print e
            return

    logline['service'] = []    
    for service in chars:
        handle = service['value_handle']
        try:
            data = device.read_by_handle(handle)
            properties = []
            for propval in propNames.keys():
                if (propval & int(service['properties'])):
                    properties.append(propNames[propval])
            print '\tuuid:' + service['uuid'] + ' handle: ' + str(handle) + " Properties:" + ','.join(properties)  + ": " + repr(''.join(data))
            service['data'] = data[0].encode('hex')
            logline['service'].append(service)
            #device_data[service] = {str(handle):repr(''.join(data))}
        except Exception,e:
            print "\tCouldn't read " + str(service)
    device.disconnect()


def parseOUI():
    """
    Put the OUI list into a python dictionary for lookup purposes
    """
    oui = {}
    with open(args.ouifile,'r') as ouidata:
        for line in ouidata.readlines():
            line = line.strip()
            s_line = line.split(' ',1)
            oui[s_line[0]] = s_line[1]
    return oui

def lookup(mac):
    """
    Parses the MAC address, extracts the OUI, searches the OUI dictionary for a match and returns any results.
    """
    tmp_mac = mac.replace(':','')[:6]
    if OUI.has_key(tmp_mac):
        return OUI[tmp_mac]
    else:
        return mac

#'5C:31:3E:54:2F:FB'
scanned_list = []
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--oui', action='store', dest='ouifile', required=False, type=str, default='oui.txt')
    parser.add_argument('-l', '--logfile', action="store", dest='logfile', required=True, type=str, default='log.txt')
    parser.add_argument('-i', '--listen_interface', action="store", dest='listen_interface', required=False, type=str, default="hci0")
    parser.add_argument('-t', '--talk_interface', action="store", dest='talk_interface', required=False, type=str, default="hci1")
    #TODO: add database support?
    args = parser.parse_args()

    print "Parsing OUI..."
    try:
        OUI = parseOUI()
    except Exception,e:
        print e
        print "OUI could not be parsed - check your OUI file\ncontinuing..."

    outlog = open(args.logfile,'a+')

    print "Looking for devices..."
    service = DiscoveryService(args.listen_interface)
    while 1:
        try:
            devices = service.discover(3)
            for address in devices:
                if address not in scanned_list:
                    logline = {}
                    logline['device'] = address
                    print "Found new device -- enumerating"
                    manuf = lookup(address)
                    print "\t Manuf: " + manuf + ':' + address
                    logline['manuf'] = manuf
                    scanned_list.append(address)
                    enumerate(address)
                    outlog.write(json.dumps(logline))
        except RuntimeError,e:
            print "Runtime err:" + str(e)
            service = DiscoveryService("hci0")
            pass
        except KeyboardInterrupt:
            print "exit"
            exit()
