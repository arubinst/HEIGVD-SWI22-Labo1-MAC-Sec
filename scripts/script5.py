# Auteurs : Peguiron Adrien, Viotti Nicolas

from scapy.all import *
from threading import Thread
import pandas
import time
import os

sta = []
SSID = input("Entrez le SSID recherché\n")

def callback(packet):
    if packet.haslayer(Dot11ProbeReq):
        foundSSID = packet.info.decode()
        if foundSSID == SSID and packet[Dot11].addr2 not in sta: # Si la station n'est pas déjà enregistrée
            sta.append(packet[Dot11].addr2)


def main():
    IFACE = "wlan0" # Interface à utiliser

    sniff(prn=callback, iface=IFACE, timeout=20)
    print("Les stations suivantes recherchent le wifi " + SSID + "")
    for s in sta:
        print(s)

if __name__ == "__main__":
    main()
