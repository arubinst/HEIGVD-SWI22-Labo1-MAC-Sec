# Auteurs : Peguiron Adrien, Viotti Nicolas

#Largement (complètement) inspiré par le maître Vivek Ramachandran, https://www.youtube.com/watch?v=_OpmfE43AiQ

#!/bin/python

from scapy.all import *
import socket

IFACE = "wlan0" #Interface à utiliser

hidden_ssid_aps = set()

def PacketHandler(pkt) :
    if pkt.haslayer(Dot11Beacon):
        if pkt.info == b'\x00\x00\x00\x00\x00' : #Si le wifi n'a pas de SSID,  donc une longueur de 0, on peut donc définir qu'il est "caché"
            if pkt.addr3 not in hidden_ssid_aps:
                hidden_ssid_aps.add(pkt.addr3)
                print("Réseau invisible trouvé ! BSSID: " + pkt.addr3)

        elif pkt.haslayer(Dot11ProbeResp) and (pkt.addr3 in hidden_ssid_aps): # On cherche à récupérer le nom d'un réseau caché déjà rencontré
            print("SSID découvert: " + pkt.info + " " + pkt.add3)

sniff(prn=PacketHandler, iface=IFACE, timeout=10)