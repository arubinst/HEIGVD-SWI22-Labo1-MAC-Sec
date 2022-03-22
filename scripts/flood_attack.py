#!/usr/bin/env python3
from scapy.all import *
import argparse
import string

def send_beacon(ssid, bssid_sender):
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2=bssid_sender, addr3=bssid_sender)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
    
    # prepare packet with all parameters
    packet = RadioTap()/dot11/beacon/essid
    
    print("Press Ctrl+C if you want to stop sending packets")
    
    # send packet
    sendp(packet, iface=interface, inter=0.100, loop=1)
    

if __name__ == "__main__":
    
    interface = "wlp1s0mon"

    parser = argparse.ArgumentParser(description="A python script for sending fake ssid")
    parser.add_argument("-f" , "--file", help="File with ssid names")
    args = parser.parse_args()
    
    # if user did not add a file in argument, we ask him to choose the number of APs that he
    # wants to generate
    if(len(sys.argv) == 1):
        number = int(input("Choose the number of APs that you want to generate: "))
        # we generate a random lowercase string (10 caracters) and a random MAC for the bssid
        for i in range(number):
            ssid = ''.join((random.choice(string.ascii_lowercase) for x in range(10)))
            send_beacon(ssid, RandMAC())
    else:
        file1 = open(args.file, 'r')
        lines = file1.readlines()
        
        # we read the file line by line and generate a random MAC for the bssid
        for line in lines:
            send_beacon(line.strip(), RandMAC())
    
