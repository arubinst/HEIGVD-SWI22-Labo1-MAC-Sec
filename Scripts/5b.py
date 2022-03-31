#!/usr/bin/env python3  
# -*- coding: utf-8 -*- 
# # Author : Quentin Le Ray, Ryan Sauge
# Date : 31.03.2022
# Développer un script en Python/Scapy capable de générer une 
# liste d'AP visibles dans la salle et de STA détectés et déterminer quelle STA est associée à quel AP
# Remarques : Pour trouver les STA connectés à des AP, on récupère les paquets data.

from scapy import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Elt, Dot11ProbeResp
from scapy.sendrecv import sniff, sendp
from scapy.utils import hexdump
import sys
import argparse
import os
import time
import binascii

listSTA = {}
banIP = ["ff:ff:ff:ff:ff:ff", "33:33:00:00:00:01", "33:33:00:00:00:02"]

class SCANNER:
    def __init__(self):
        self.ap_list = {}
        self.interface = ""
        self.channelTarget = {1:6,6:11,11:1}
        self.actualChannel = 1


"""
Get packet
Sources :
# https://xavki.blog/securite-scapy-scanner-les-reseaux-wifi-ssid-et-leur-adresse-mac/
# https://www-npa.lip6.fr/~tixeuil/m2r/uploads/Main/PROGRES2018_APIScapy.pdf
"""
def packetRecup(scanner):
    #probeRespo : contient les informations sur ce que supporte la STA
	def scan(paquet):
		if paquet.haslayer(Dot11Beacon) or paquet.haslayer(Dot11ProbeResp):
            #type 0 => management
			#subtype 8 =>Beacon
			if paquet.type == 0 and paquet.subtype == 8:
				if str(paquet.info, "utf-8") not in scanner.ap_list:
					scanner.ap_list[paquet.addr2] = paquet
					print("Réseau SSID: %s et MAC address: %s " % (paquet.info, paquet.addr2))
					print("Réseau SSID: %s et MAC address: %s " % (paquet.info, paquet.addr2))
					print("Réseau BSSID: %s" % ( paquet[Dot11].addr3))
		#type 2 => data
		#subtype 0 =>data
		if paquet.type == 2 and paquet.subtype == 0:
			if paquet.addr1 not in banIP and paquet.addr2 not in banIP:
				#On vérifie que l'AP est dans la liste
				#Si présent => Ajout de la STA dans la liste
				if paquet.addr2 in scanner.ap_list:
					pkt = scanner.ap_list.get(paquet.addr2)
					if( pkt.addr2 == paquet.addr2):
						listSTA[paquet.addr1] = paquet.addr2
					else:
						listSTA[paquet.addr1] = paquet.addr1
				if paquet.addr1 in scanner.ap_list:
					pkt = scanner.ap_list.get(paquet.addr1)
					if(pkt.addr2 == paquet.addr1):
						listSTA[paquet.addr2] = paquet.addr2
					else:
						listSTA[paquet.addr2] = paquet.addr1
	return scan

"""
Permet des sniffer les paquets réseaux en sautant de canal
L'utilisateur doit effecuter une interruption de clavier pour passer au canal suivant
"""
def channel_hopper(scanner):
    channelLists = [1, 6, 11]
    for i in channelLists:
        try:
            print(f"iwconfig {scanner.interface} channel {i}")
            os.system(f"iwconfig {scanner.interface} channel {i}")
            time.sleep(0.7)
            sniff(iface=scanner.interface, prn=packetRecup(scanner))
        except KeyboardInterrupt:
           continue


def main():
	scanner = SCANNER()
	# Passage puis récupération des arguments
	parser = argparse.ArgumentParser(prog="Scapy wifi scanner",
                                    usage="%(prog)s -i wlan0mon",
                                    description="5b détection de clients et réseaux",
                                    allow_abbrev=True)
	parser.add_argument("-i", "--Interface", required=True,
                        help="Interface pour envoyer les paquets, doit être en mode monitor")
	

	args = parser.parse_args()

	scanner.interface = args.Interface 

	# Sniffer les paquets
	channel_hopper(scanner)

	pt = 0
	print("List des réseaux connectés")
	for key, values in scanner.ap_list.items():
		print(f"SSID {str(values.info, 'utf-8')}" )
		print(f"MAC {values.addr2}" )
		print(f"Canal{str(int(ord(values[Dot11Elt:3].info)))}" )

	print("Liste des STA connectés avec l'adresse MAC de l'AP")
	for key, values in listSTA .items():
		print("STA || AP ")
		print(f"MAC {key} || {values}")
main()



