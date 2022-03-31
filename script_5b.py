 #! /usr/bin/env python

# Rebecca Tevaearai , Rosy-Laure Wonjamouna


import argparse
from scapy.all import *


# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-i", "--interface", help = "interface réseau à utiliser")


# Read arguments from command line
args = parser.parse_args()

access_points = []  # On initialise une liste de points d'accès
ap_sta = [] # On intialise une liste de paires AP_STA appairées
def get_packets(packet) :
    if packet.haslayer (Dot11) :
        if packet.type == 0 and packet.subtype == 8 :   # Si le paquet capturé est un beacon frame 
            if packet[Dot11].addr2 not in access_points : 
                access_points.append(packet[Dot11].addr2)   # Si la source du beacon frame c'est à dire l'AP n'est pas encore dans la liste, on le rajoute à la liste d'AP
        if packet.type == 2 :    #  Si le paquet capturé est un data frame
            if packet[Dot11].addr1 in access_points :       # Si l'adresse de destination de ce data frame est un AP
                 if packet[Dot11].addr1!= "ff:ff:ff:ff:ff:ff": # On s'assure que l'envoi de la data frame n'est pas en broadcast
                     if (packet[Dot11].addr1, packet[Dot11].addr2) not in ap_sta :
                        ap_sta.append((packet[Dot11].addr1, packet[Dot11].addr2))
                        print("AP : ", packet[Dot11].addr1)        # On imprime l'adresse de destination qui est un AP  
                        print("STA: ", packet[Dot11].addr2)        # On imprime l'adresse source qui est une STA
                        print("\n")

sniff(iface = args.interface , prn = get_packets)              
 