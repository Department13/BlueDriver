#!/usr/bin/python
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
            # We have a bunch of RuntimeErrors raised for various reasons by the GATTLib library -- lets handle those, then maybe fork GATTLib and get those to be more specific
            if type(e) == RuntimeError:
                
                if e.message == "Channel or attrib not ready":
                    if deviceHandle.is_connected():
                        if args.debug == True: print "Device error"
                    break # i don't think we can win
                    #print 'w'
                    #pdb.set_trace()
                    #TODO: maybe see if it's connected or not?
                    #flag += 1 # we don't want to get stuck here.
                    #continue

                elif e.message == "Already connecting or connected":
                    if deviceHandle.is_connected():
                        break
                    else:
                        time.sleep(3)
                        if args.debug == True: print '\t Waiting for response to connection...'
                    continue

                else:
                    #errnum = int(e.message.split()[-1][1:-1]) #remove the ( and ) from the error number
                    time.sleep(1)
                    if args.debug == True: print '!!!' + e.message
                    continue

            print e
            flag += 1
    return deviceHandle
        
def enumerate(address):
    """
    Attempts to discover all characteristics and dump all values from the device
    device( services( charactaristics( values )))
    """
    device = connect(address)

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

scanned_list = []
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--oui', action='store', dest='ouifile', required=False, type=str, default='oui.txt')
    parser.add_argument('-l', '--logfile', action="store", dest='logfile', required=False, type=str, default='log.txt')
    parser.add_argument('-i', '--listen_interface', action="store", dest='listen_interface', required=False, type=str, default="hci0")
    parser.add_argument('-d','--debug', action="store", dest="debug", required=False, type=bool, default=False)
    #parser.add_argument('-t', '--talk_interface', action="store", dest='talk_interface', required=False, type=str, default="hci1")
    #TODO: add database support?
    args = parser.parse_args()

    print "Parsing OUI..."
    try:
        OUI = parseOUI()
    except Exception,e:
        if args.debug == True: print e
        print "OUI could not be parsed - check your OUI file\ncontinuing..."

    if args.logfile == True:
        outlog = open(args.logfile,'a+')
    # if we dont specifically want a log file, then just make a tmpfile and shove it there for now
    else:
        outlog = open('/tmp/bluedriver','a+')

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
            if args.debug == True: print "Runtime err:" + str(e)
            service = DiscoveryService("hci0")
            pass
        except KeyboardInterrupt:
            print "exit"
            exit()
