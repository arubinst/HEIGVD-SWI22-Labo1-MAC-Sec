#!/usr/bin/env python3  
# -*- coding: utf-8 -*- 
# # Author : Quentin Le Ray, Ryan Sauge
# Date : 31.03.2022
# Développer un script en Python/Scapy : 
# capable de lister toutes les STA qui cherchent activement un SSID donné
"""
Sources :
https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/
https://xavki.blog/securite-scapy-scanner-les-reseaux-wifi-ssid-et-leur-adresse-mac/
https://www-npa.lip6.fr/~tixeuil/m2r/uploads/Main/PROGRES2018_APIScapy.pdf
"""


from scapy import *
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff
from fakeChannel import SCANNER
import sys
import argparse
import os
import time




import binascii

listSTA = {}
def packetRecup(scanner, target):
	def scan(paquet):
		if paquet.haslayer(Dot11):
			# 0 => management // 4 =>Probe request
			if paquet.type == 0 and paquet.subtype == 4 and str(paquet.info, "utf-8") == target:
				# addr1 => destination
				# addr2 => source
				if str(paquet.addr2) not in listSTA:
					listSTA[paquet.addr2] = paquet
					print("Réseau SSID: %s et MAC address AP: %s " % (paquet.info, paquet.addr1))
					print("Réseau SSID: %s et MAC address STA: %s " % (paquet.info, paquet.addr2))
					return
	return scan

def channel_hopper(scanner, target):
	channelLists = [1, 6, 11]
	for i in channelLists:
		try:
			print(f"iwconfig {scanner.interface} channel {i}")
			os.system(f"iwconfig {scanner.interface} channel {i}")
			scanner.actualChannel = i
			time.sleep(0.5)
			sniff(iface=scanner.interface, prn=packetRecup(scanner , target))
		except KeyboardInterrupt:
			continue

def main():
	scanner = SCANNER()
	# Passage puis récupération des arguments
	parser = argparse.ArgumentParser(prog="Scapy wifi scanner",
                                    usage="%(prog)s -i wlan0mon -t target",
                                    description="5a détection de clients",
                                    allow_abbrev=True)
	parser.add_argument("-i", "--Interface", required=True,
                        help="Interface pour envoyer les paquets, doit être en mode monitor")
	
	parser.add_argument("-t", "--Target", required=True,
                        help="SSID cible")
	
	args = parser.parse_args()


	scanner.interface = args.Interface 

	# Sniffer les paquets
	channel_hopper(scanner, args.Target)

	print("Liste de toutes les STA")
	for key, values in listSTA .items():
		print(f"MAC {key}" )
main()



