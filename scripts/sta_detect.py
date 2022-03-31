#!/bin/python3
import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11

STAs = []


def packet_handler(p):
    """
    Packet handler to analyse active Probe requests and discover new ssids
    :param p: the packet to analyse
    """
    if p.haslayer(Dot11ProbeReq):
        ssid = p.info.decode("utf-8")
        sta = p.addr2
        # Store the STAs looking for the target network
        if ssid == args.SSID and sta not in STAs:
            STAs.append(sta)
            print(sta)


def search_stas():
    """
    Sniff for active probe request on the targeted network
    :return:
    """
    print("Targeted network:", args.SSID)
    print("<STAs>")
    sniff(iface=args.Interface, prn=packet_handler)


# Args parsing
parser = argparse.ArgumentParser(prog="Scapy Fake channel Evil Tween attack",
                                 usage="evil_twin_probe_request.py -i wlp2s0mon -b 00:11:22:33:44:55 [-t 10]",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to use, needs to be set to monitor mode")
parser.add_argument("-s", "--SSID", required=True,
                    help="The SSID of the network to target")

args = parser.parse_args()

# start the detection
search_stas()
