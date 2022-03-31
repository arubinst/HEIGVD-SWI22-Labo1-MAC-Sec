# This script listen to STA sending probe request for a specific SSID.
# It print the STA mac addresses when found.
#
# To interupt the script use ctrl+c 

import sys
from scapy.all import *

# set interface
iface = "wlan0mon"

# STA list
device_list = []

# SSID we are looking for
ssid = ""


# Function that handle sniffed packets
def PacketHandler(pkt):
    # If we got a probe request
    if pkt.haslayer(Dot11ProbeReq):
        # if the SSID is the one we are looking for, and the mac addr isn't in the list
        if pkt.info.decode("UTF-8") == ssid and  pkt.info.decode("UTF-8") not in device_list:
            # Add the new STA mac addr and print it
            device_list.append(pkt.info.decode("UTF-8"))
            print(pkt.addr2)

if __name__ == "__main__":
    # handle argument
    if len(sys.argv) < 2 or sys.argv[1] == "":
        print("Please provide a ssid as an argument")
        exit(1)
    else:
        ssid = sys.argv[1]

    print("STA looking for %s AP: " % (ssid))

	# Start sniffer
    sniff(iface=iface, prn = PacketHandler)
