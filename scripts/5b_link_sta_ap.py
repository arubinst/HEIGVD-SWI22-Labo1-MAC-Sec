#!/usr/bin/env python3
# Authors: Jean-Luc Blanc & Noémie Plancherel
# import all the needed libraries
import sys
from subprocess import *
from scapy.all import *
import argparse

# define variables
BROADCAST_ADDRESS = "ff:ff:ff:ff:ff:ff"
list_ap_sta = []


# Our function that links STA to an AP
# for this function, we simply add the address of each different station that is linked to an AP
def link(p):
    if p.type == 2:
        if p.addr1 != BROADCAST_ADDRESS and p.addr2 != BROADCAST_ADDRESS and p.addr3 is not None:
            if p.addr1 != p.addr3:
                sta_ap = (p.addr1, p.addr3)
            else:
                sta_ap = (p.addr2, p.addr3)
            
            if sta_ap not in list_ap_sta:
                list_ap_sta.append(sta_ap)
                print(sta_ap[0]+"              "+sta_ap[1])

                
# our main function             
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A python script for searching STA associated to AP')
    parser.add_argument('interface', action="store", help="Specify a monitoring interface (ex. mon0)", default=False)
    args = parser.parse_args()
    print("\nSTA                               AP")
    sniff(iface=args.interface,prn=link, store=0)                    
    print ("\n")
    print ("Exiting!")
