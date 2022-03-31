# Authors : Delphine Scherler & Wenes Limem
# Date : 31.03.2022
# Source : https://www.geeksforgeeks.org/finding-all-wifi-devices-using-scapy-python/
# Description : Script qui génère une liste d'AP visibles et de STA détectés et détermine quelle STA est associée à quel
# AP.

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

devices = set()
sta_ap = {0: ["STAs", "APs"]}
# change it with your target SSID
# target_ssid = "LeChatelard"
target_ssid = "Sunrise_Wi-Fi_6AEC90"
interface = "wlan0"
t_out = 15


# find APs and associated STAs
def find_STA_AP(pkt):
    if pkt.haslayer(Dot11):
        dot11_layer = pkt.getlayer(Dot11)
        # find devices and add to list
        addr1 = dot11_layer.addr1
        if (addr1 not in sta_ap) and dot11_layer.addr3:
            # find AP and add to list
            addr3 = dot11_layer.addr3
            sta_ap[addr1] = [addr1, addr3]


if __name__ == "__main__":
    print("Sniffing access points for", t_out, "seconds")
    sniff(prn=find_STA_AP, iface=interface, timeout=t_out)
    print("Associating stations to APs ...")
    # Display STAs and APs MACs
    for i in sta_ap:
        print(sta_ap.get(i))
