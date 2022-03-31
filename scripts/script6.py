from scapy.all import *
from threading import Thread
import pandas
import time
import os

apAddr = []
staAddr = []
staAndApp = []

def callback(packet):
    # Detection des APs
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        if packet[Dot11].addr3 not in apAddr:
            #print(packet[Dot11].info.decode() + packet[Dot11].addr3)
            apAddr.append(packet[Dot11].addr3)

def callback2(packet):
    if packet.haslayer(Dot11QoS) and packet[Dot11].addr1 != "ff:ff:ff:ff:ff:ff":
        if packet[Dot11].addr3 in apAddr:
            sap = "La STA " + packet[Dot11].addr2 + " est connectée à l'AP " + packet[Dot11].addr3
            if sap not in staAndApp:
                staAndApp.append(sap)
        if packet[Dot11].addr2 not in staAddr:
            staAddr.append(packet[Dot11].addr2)

def main():
    iface = "wlan0"

    sniff(prn=callback, iface=iface, timeout=10)
    sniff(prn=callback2, iface=iface, timeout=10)
    print("APs disponibles : ")
    for a in apAddr:
        print (a)

    print("STAs disponibles : ")
    for s in staAddr:
        print(s)

    print("Connexions : ")
    for t in staAndApp:
        print(t)

if __name__ == "__main__":
    main()
