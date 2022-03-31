#!/usr/bin/env python3
# Authors: Jean-Luc Blanc & Noémie Plancherel
# import all the needed libraries
import sys
from subprocess import *
from scapy.all import *
import argparse
import texttable as text_t                                       

# define variables
hidden_ssid = dict()

# function to find the hidden ssid
def find(p):
    if p.haslayer(Dot11Elt):
        ssid = p.info.decode().replace("\000", "")
        bssid = p[Dot11].addr3
        if p.haslayer(Dot11Beacon) and bssid not in hidden_ssid.keys() and ssid == "":
            hidden_ssid[bssid] = "SSID hidden"
        elif (p.type == 0 and p.subtype == 5) and bssid in hidden_ssid.keys():
            hidden_ssid[bssid] = ssid

# our main function             
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A python script to find hidden ssid')
    parser.add_argument('interface', action="store", help="Specify a monitoring interface (ex. mon0)", default=False)
    args = parser.parse_args()
    sniff(iface=args.interface,prn=find, store=0)
    print(hidden_ssid)                 
    print ("\n")
    print ("Exiting!")
