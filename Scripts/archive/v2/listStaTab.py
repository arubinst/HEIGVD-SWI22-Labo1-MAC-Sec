"""

"""

from scapy import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Elt, Dot11ProbeResp
from scapy.sendrecv import sniff, sendp
from scapy.utils import hexdump
#from fakeChannel import SCANNER
#from fakeChannel import channel_hopper 
import sys
import argparse
import os
import time


"""ch="auto"
os.system(f"iwconfig wlan0mon channel 1")
"""
# HashMap<String,String> streetno=new HashMap<String,String>();

# https://xavki.blog/securite-scapy-scanner-les-reseaux-wifi-ssid-et-leur-adresse-mac/
# https://www-npa.lip6.fr/~tixeuil/m2r/uploads/Main/PROGRES2018_APIScapy.pdf
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
					# print("Réseau SSID: %s et MAC address: %s " % (paquet.info, paquet.addr2))
					# print("Réseau SSID: %s et MAC address: %s " % (paquet.info, paquet.addr2))
					# print("Réseau BSSID: %s" % ( paquet[Dot11].addr3))
					# print("channel : " + str(int(ord(paquet[Dot11Elt:3].info))))
					# print("capabiliy : " + paquet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
					# {Dot11ProbeResp:%Dot11ProbeResp.cap%}"))
					#return "Réseau SSID: %s et MAC address: %s " % (pkt.info, pkt.addr2)
			#type 2 => data
			#subtype 0 =>data
		if paquet.type == 2 and paquet.subtype == 0:
			if paquet.addr1 in banIP or paquet.addr2 in banIP:
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
def channel_hopper(scanner):
    channelLists = [1, 6, 11]
    for i in channelLists:
        try:
            print(f"iwconfig {scanner.interface} channel {i}")
            os.system(f"iwconfig {scanner.interface} channel {i}")
            time.sleep(0.5)
            #os.system("iw dev %s set channel %d" % (scanner.interface, i))
            sniff(iface=scanner.interface, prn=packetRecup(scanner))
        except KeyboardInterrupt:
           continue


def main():
	scanner = SCANNER()
	# Passing arguments
	parser = argparse.ArgumentParser(prog="Scapy wifi scanner",
                                    usage="%(prog)s -i wlan0mon",
                                    description="Scapy scanner detect STA",
                                    allow_abbrev=True)
	parser.add_argument("-i", "--Interface", required=True,
                        help="The interface that you want to send packets out of, needs to be set to monitor mode")
	

	args = parser.parse_args()

    # sniff(iface=args.Interface, prn=packetRecup(scanner))

	scanner.interface = args.Interface # Interface name here
	channel_hopper(scanner)

	pt = 0
	print("List of detected networks")
	for key, values in scanner.ap_list.items():
		print(f"SSID {str(values.info, 'utf-8')}" )
		print(f"MAC {values.addr2}" )

	print("List of All STA")
	for key, values in listSTA .items():
		print("STA || AP")
		print(f"MAC {key} || {values}")
main()



