 #! /usr/bin/env python

import argparse
from scapy.all import *


# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-i", "--interface", help = "interface réseau à utiliser")
parser.add_argument("-s", "--ssid", help = "ssid donné", default = 'HEIG-VD')


# Read arguments from command line
args = parser.parse_args()


# Pour obtenir une liste des SSID disponible il suffit de sniffer les paquets avec la fonction sniff sur l'interface concernée
print("Le SSID donné recherché est "+ args.ssid) # On imprime le SSID qu'on cherche
ssid = bytes(args.ssid,'UTF-8')                  # On le cast au format byte
print("Les STAs cherchant ce SSID sont :")
sta_list = []  # On initialise une liste de STA
def get_packets(packet) :
    if packet.haslayer (Dot11) :
        if packet.type == 0 and packet.subtype == 4 :   # Si le paquet capturé est une probe request
            if packet[Dot11Elt].ID == 0 :
                if packet[Dot11Elt].info == ssid :      # On checke si le SSID du paquet est égal au SSID recherché
                    if packet[Dot11].addr2 not in sta_list :
                        sta_list.append(packet[Dot11].addr2)  # Si tel est le cas, on ajoute l'adresse source de la probe request à la liste des STAs cherchant le SSID donné
                        print(packet[Dot11].addr2)              
sniff(iface = args.interface , prn = get_packets)
 