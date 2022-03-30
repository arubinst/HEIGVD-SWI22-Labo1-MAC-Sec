# Authors : Delphine Scherler & Wenes Limem
# Date : 31.03.2022
# Source : https://www.geeksforgeeks.org/finding-all-wifi-devices-using-scapy-python/

import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

devices = set()
sta_ap = {}
sta_ap[0] = ["STAs", "APs"]
target_ssid = "LeChatelard"
interface = "wlan0"
t_out = 5


# Part a) find all STAs on target SSID
def find_network(pkt):
    if pkt.haslayer(Dot11Beacon):
        # compare SSID
        if pkt[Dot11Elt].info.decode() == target_ssid:
            # extract the MAC address of the network
            mac_ap = pkt[Dot11].addr3
            return mac_ap


def find_STA(pkt):
    if pkt.haslayer(Dot11):
        dot11_layer = pkt.getlayer(Dot11)
        # find traffic on target SSID
        mac_ap = sniff(prn=find_network, iface=interface, timeout=t_out)
        if dot11_layer.addr3 == mac_ap:
            # find devices and add to list
            if dot11_layer.addr2 and (dot11_layer.addr2 not in devices):
                devices.add(dot11_layer.addr2)
              


# Part b) find all STAs and APs
def find_STA_AP(pkt):
    if pkt.haslayer(Dot11):
        dot11_layer = pkt.getlayer(Dot11)
        # find devices and add to list
        if dot11_layer.addr2 and (dot11_layer.addr2 not in sta_ap):
            addr2 = dot11_layer.addr2
            # find AP and add to list
            addr3 = dot11_layer.addr3
            sta_ap[addr2] = [addr2, addr3]


if __name__ == "__main__":
    # Part a)
    print("Sniffing stations for ",t_out)
    sniff(prn=find_STA, iface=interface, timeout=t_out)

    # Part b)
    print("Sniffing access points for ",t_out)
    sniff(prn=find_STA_AP, iface=interface, timeout=t_out)
    print("Associating stations to aps ...")
    # Display STAs and APs MACs
    for i in sta_ap:
        print(sta_ap.get(i))
