# This script try to find the real SSID when masked.
#
# It searches for empty SSID in beacons, stores the mac adresse in a list and then search for
# these mac in probe request and response to find the real SSID.
#
# When a hidden AP is found a line is written: AP MAC: 12:02:8e:8d:c5:b6 hidden on channel: 8
# When the SSID is found another line is written: AP MAC: 12:02:8e:8d:c5:b6 with SSID: example
#
# To stop the script, use ctrl+c

import os
from multiprocessing import Process
from scapy.all import *

# Interface
iface = "wlan0mon"

# Access point list
mac_list = []

# Function that handle sniffed packets
def PacketHandler(pkt):
    # If it is a beacon -> packet send by the AP
    if pkt.haslayer(Dot11Beacon):
        # If the SSID vaue is null, and the corresponding mac not already in the mac list
        if pkt.info.decode("UTF-8") == "" and pkt.addr2 not in mac_list:
            # Add the AP mac addresse to the list
            mac_list.append(pkt.addr2)
            # extract the channel number
            channel = int(ord(pkt[Dot11Elt:3].info))

            print('AP MAC: %s hidden on channel: %s' % (pkt.addr2, channel))
    # If it is a probe request or response
    elif pkt.haslayer(Dot11ProbeResp) or pkt.haslayer(Dot11ProbeReq):
        # If one of the mac addresses is in the mac list -> one of the AP found, we have the masked SSID
        if pkt.addr1 in mac_list or pkt.addr2 in mac_list:
            mac = pkt.addr1 if pkt.addr1 in mac_list else pkt.addr2
            print("AP MAC: %s with SSID: %s" % (mac, pkt.info.decode("UTF-8")))       


# function to hop through the channels. Copied from:
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

	# start the packet sniffer
	sniff(iface=iface, prn = PacketHandler)