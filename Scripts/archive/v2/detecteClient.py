from scapy import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Elt, Dot11ProbeResp
from scapy.sendrecv import sniff, sendp
from scapy.utils import hexdump
from fakeChannel import createNetwork
from fakeChannel import SCANNER
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


def packetRecup(scanner, target):
	def scan(paquet):
		if paquet.haslayer(Dot11):
			#0 => management // 4 =>Probe request
			if paquet.type == 0 and paquet.subtype == 4 and str(paquet.info, "utf-8") == target:
				if str(paquet.info, "utf-8") not in scanner.ap_list:
					scanner.ap_list[str(paquet.info, "utf-8")] = paquet
					# ap_list.append((pkt.ssid, pkt.addr2))
					print("Réseau SSID: %s et MAC address: %s " % (paquet.info, paquet.addr1))
					print("Réseau SSID: %s et MAC address: %s " % (paquet.info, paquet.addr2))
					# return "Réseau SSID: %s et MAC address: %s " % (pkt.info, pkt.addr2)
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
            #os.system("iw dev %s set channel %d" % (scanner.interface, i))
			sniff(iface=scanner.interface, prn=packetRecup(scanner , target))
		except KeyboardInterrupt:
			continue

def main():
	scanner = SCANNER()
        # Passing arguments
	parser = argparse.ArgumentParser(prog="Scapy wifi scanner",
                                    usage="%(prog)s -i wlan0mon -t target",
                                    description="Scapy scanner detect STA",
                                    allow_abbrev=True)
	parser.add_argument("-i", "--Interface", required=True,
                        help="The interface that you want to send packets out of, needs to be set to monitor mode")
	
	parser.add_argument("-t", "--Target", required=True,
                        help="The SSID target")
	
	args = parser.parse_args()

    #sniff(iface=args.Interface, prn=packetRecup(scanner))

	scanner.interface = args.Interface # Interface name here
	channel_hopper(scanner, args.Target)

	
	if args.Target in scanner.ap_list :
		pkt = scanner.ap_list.get(args.Target)
		channel = scanner.actualChannel
		print (channel)
		ch = scanner.channelTarget.get(channel)
		createNetwork(bytes(args.Target, 'utf-8'), scanner, ch)
main()

