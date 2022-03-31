#!/bin/python3
import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt

STA_BSSIDs = []


def packet_handler(p):
    """
    Packet handler to analyse active data frames and discover new sta-bssid
    :param p: the packet to analyse
    """

    # Check for data frames
    if p.type == 2:
        # Get the direction of the data
        to_DS = p.FCfield & 0x1 != 0
        from_DS = p.FCfield & 0x2 != 0

        if to_DS and not from_DS:
            bssid = str(p.addr1)
            sta = str(p.addr2)
        elif not to_DS and from_DS:
            bssid = str(p.addr2)
            sta = str(p.addr1)
        else:
            # We don't handle the IBSS and WDS cases
            return

        # Ignore the broadcast
        if sta == "ff:ff:ff:ff:ff:ff":
            return

        if (sta, bssid) not in STA_BSSIDs:
            STA_BSSIDs.append((sta, bssid))
            print("{}    {}".format(sta, bssid))


def search_stas():
    """
    Sniff for stas and their associated AP
    :return:
    """
    print("    <STAs>                <APs>")
    sniff(iface=args.Interface, prn=packet_handler)


# Args parsing
parser = argparse.ArgumentParser(prog="Station Access point detection",
                                 usage="client_network_detect.py -i wlp2s0mon",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to use, needs to be set to monitor mode")

args = parser.parse_args()

# Search for STAs and their APs
search_stas()
