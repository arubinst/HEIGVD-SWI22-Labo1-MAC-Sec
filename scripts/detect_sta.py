#!/usr/bin/env python3 
from scapy.all import * 
import argparse 
                                                       
ssid_wanted = 0 
all_STAs = set()
 
# function that handles all received probe request                                                       
def phandle(p):                           
    if p.haslayer(Dot11ProbeReq):       
        # get STA bssid
        bssid = p.addr2
        if p.haslayer(Dot11Elt): 
            # get ssid of the packet
            ssid = p.info.decode()
            # check if probe request is looking for the given ssid and if it is an unknown STA
            if ssid == ssid_wanted and bssid not in all_STAs: 
                all_STAs.add(bssid)
                print("STA (%s) is looking for the given SSID (%s)" % (bssid, ssid))
                 
                            
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script that lists all STAs that are looking for a given SSID') 
    parser.add_argument('interface', action="store", help="Specify a monitoring interface (ex. mon0)", default=False) 
    parser.add_argument("ssid", action="store", help="Specify a ssid that you are looking for (ex. McDonald's)") 
    args = parser.parse_args() 
    ssid_wanted = args.ssid 
    sniff(iface=args.interface,prn=phandle, store=0) 
