# The script give a liste of station associated to access point
# It begins by listing the AP accessible, and then search in 'block ack' packet
# to find the AP mac adresse.
# it print a pair when found.
#
# To stop the script, use ctrl+c

import os
from multiprocessing import Process
from scapy.all import *

# Set inteface
iface = "wlan0mon"

# AP list
ap_list = []
# List of pair AP <-> STA
assoc_list = []

# Function that handle sniffed packets
def PacketHandler(pkt):
    # Filter on beacon -> packet send by the AP, and not already in the mac list
    if pkt.haslayer(Dot11Beacon) and pkt.addr2 not in ap_list:
        ap_list.append(pkt.addr2)

    # If the packet is a 'block ack' (subtype 9) -> datas are exchanged between STA and AP
    if pkt.haslayer(Dot11) and pkt.subtype == 9:
        # If on of the mac addresses is in the list, it means that the other one is the 
        # associated STA.
        # Pairs are store in this order: (AP, STA)
        if pkt.addr1 in ap_list:
            if (pkt.addr1, pkt.addr2) not in assoc_list:
                assoc_list.append((pkt.addr1, pkt.addr2))
                print("%s   %s" % (pkt.addr1, pkt.addr2))
        elif pkt.addr2 in ap_list:
            if (pkt.addr2, pkt.addr1) not in assoc_list:
                assoc_list.append((pkt.addr2, pkt.addr1))
                print("%s   %s" % (pkt.addr2, pkt.addr1))

# # function to hop through the channels. Copied from:		
# https://charlesreid1.com/wiki/Scapy/AP_Scanner#Channel_Hopper
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,12)
            os.system("iw dev %s set channel %d" % (iface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
	# Start the channel hopper
    p = Process(target = channel_hopper)
    p.start()

    print("APs                 STAs")

    # start the packet sniffer
    sniff(iface=iface, prn = PacketHandler)