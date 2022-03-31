#!/usr/bin/env python3

"""
Author: Rébecca Tevaearai, 

Created: 26th March, 2022

"""

from scapy.all import *
from argparse import ArgumentParser as AP

ssid_list = []
ap_list = []

if __name__ == '__main__':
    parser = AP(description = "Evil twin script")
    parser.add_argument("-i", "--interface", required = True, help = "the interface name")
    args = parser.parse_args()

    def PacketHandler(pkt):
        if pkt.haslayer(Dot11ProbeReq):
            if len(pkt.info) > 0 and pkt.addr1 != 'ff:ff:ff:ff:ff:ff':
                ssid_list.append(pkt)
                print('STA:', pkt.addr2, ' AP:', pkt.addr1)

    sniff(iface = args.interface, count = 0, prn = PacketHandler, store = 0)
