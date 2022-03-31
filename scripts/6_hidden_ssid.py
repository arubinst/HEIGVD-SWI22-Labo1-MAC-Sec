#!/usr/bin/env python3
# Authors: Jean-Luc Blanc & Noémie Plancherel
# import all the needed libraries
import sys
from subprocess import *
from scapy.all import *
import argparse
import texttable as text_t                                       

# define variables
hidden_ssid = dict()

# function to find the hidden ssid
def find(p):
    if p.haslayer(Dot11Elt):
		# on enlève les caractères "vide" du ssid "invisible"
        ssid = p.info.decode().replace("\000", "")
		# on récupère le bssid
        bssid = p[Dot11].addr3
		# Si notre packet est bien un beacon, et que le bssid n'est pas déjà dans notre liste et que le ssid est bien "vide"
		# alors on ajoute le bssid dans la liste et on le print
		# (ce sont les conditions qui nous permettent de "valider" le fait qu'il s'agit d'un réseau invisible
        if p.haslayer(Dot11Beacon) and bssid not in hidden_ssid.keys() and ssid == "":
            hidden_ssid[bssid] = "SSID hidden"
            print(hidden_ssid) 
		# Ici on gère le cas où on récupère un Probe Response (type 0 et subtype 5) se connectant à un de nos SSID "cachés"
        elif (p.type == 0 and p.subtype == 5) and bssid in hidden_ssid.keys():
            hidden_ssid[bssid] = ssid
            print(hidden_ssid) 

# our main function             
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A python script to find hidden ssid')
    parser.add_argument('interface', action="store", help="Specify a monitoring interface (ex. mon0)", default=False)
    args = parser.parse_args()
    sniff(iface=args.interface,prn=find, store=0)
    print ("\n")
    print ("Exiting!")
