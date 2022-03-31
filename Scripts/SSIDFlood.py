#!/usr/bin/env python3  
# -*- coding: utf-8 -*- 
# Author : Quentin Le Ray, Ryan Sauge
# Date : 31.03.2022
# Développer un script en Python/Scapy : 
# Développer un script en Python/Scapy capable d'inonder la salle avec des SSID dont le nom correspond 
# à une liste contenue dans un fichier text fournit par un utilisateur. Si l'utilisateur ne possède pas une liste, 
# il peut spécifier le nombre d'AP à générer. Dans ce cas, les SSID seront générés de manière aléatoire.
"""
Sources :
https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/
https://xavki.blog/securite-scapy-scanner-les-reseaux-wifi-ssid-et-leur-adresse-mac/
https://www-npa.lip6.fr/~tixeuil/m2r/uploads/Main/PROGRES2018_APIScapy.pdf
"""

import sys

from scapy import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Elt, Dot11ProbeResp
from scapy.sendrecv import sniff, sendp
from scapy.utils import hexdump

import _thread
import random
import argparse
from fakeChannel import createNetwork
from fakeChannel import SCANNER



def main():
    srcMacAddress = "22:22:22:22:22:22"
    apMacAddress = '33:33:33:33:33:33'

    characters = "123456789abcdefghijk"

    scanner = SCANNER()
        # Passing arguments
    parser = argparse.ArgumentParser(prog="SSID flood attack",
                                    usage="%(prog)s -i wlan0mon -c channel -f file",
                                    description="Scapy SSID flood",
                                    allow_abbrev=True)
    parser.add_argument("-i", "--Interface", required=True,
                        help="The interface that you want to send packets out of, needs to be set to monitor mode")
    parser.add_argument("-c", "--Channel", required=True,
                        help="The channel where the fake network are created")
    parser.add_argument("-f", "--File", required=False,
                        help="Path for the file with network fake ssid")
  
    args = parser.parse_args()


    ssidList = []
    scanner.interface = args.Interface
    if args.File != None:
        FILE = open(args.File, 'r')
        ssidList = FILE.readlines()
    else:
        nb = input("Nombre d'AP à générer")
        l = list(characters)
        for i in (0, int(nb)):
            random.shuffle(l)
            ssidList.append(''.join(l))
    for ssid in ssidList:
        # Lancement des faux réseaux avec des threads
        _thread.start_new_thread(createNetwork, (bytes(ssid, "utf-8"), scanner, int(args.Channel) ))
    while(True):
        pass
