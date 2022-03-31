# Auteurs : Peguiron Adrien, Viotti Nicolas

from scapy.all import *
from threading import Thread
import pandas
import time
import os

apAddr = []
staAddr = []
staAndApp = []

def callback(packet):
    # Détection des APs
    if packet.haslayer(Dot11Beacon):
        # Extrait l'adresse MAC du réseau
        if packet[Dot11].addr3 not in apAddr:
            apAddr.append(packet[Dot11].addr3)

def callback2(packet):
    if packet.haslayer(Dot11QoS) and packet[Dot11].addr1 != "ff:ff:ff:ff:ff:ff": # on vérifie que ce ne soit pas un message broadcast
        if packet[Dot11].addr3 in apAddr: 
            sap = "La STA " + packet[Dot11].addr2 + " est connectée à l'AP " + packet[Dot11].addr3
            if sap not in staAndApp:
                staAndApp.append(sap)
        if packet[Dot11].addr2 not in staAddr:
            staAddr.append(packet[Dot11].addr2)

def main():
    IFACE = "wlan0" # Interface à utiliser

    sniff(prn=callback, iface=IFACE, timeout=10)
    sniff(prn=callback2, iface=IFACE, timeout=10)
    print("APs disponibles : ")
    for ap in apAddr:
        print (ap)

    print("STAs disponibles : ")
    for sta in staAddr:
        print(sta)

    print("Connexions : ")
    for sap in staAndApp:
        print(sap)

if __name__ == "__main__":
    main()
