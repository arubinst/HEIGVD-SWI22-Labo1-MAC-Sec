# Authors : Delphine Scherler & Wenes Limem
# Date : 31.03.2022
# Source : https://www.geeksforgeeks.org/finding-all-wifi-devices-using-scapy-python/
# Description : Script permettant de lister toutes les STA qui cherchent activement un SSID donné

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq

devices = set()
sta_ap = {0: ["STAs", "APs"]}
# change it with your target SSID
# target_ssid = "LeChatelard"
target_ssid = "Sunrise_Wi-Fi_6AEC90"
interface = "wlan0"
t_out = 15


# find informations about target SSID
def find_network(pkt):
    if pkt.haslayer(Dot11Beacon):
        # compare SSID
        if pkt[Dot11Elt].info.decode() == target_ssid:
            # extract the MAC address of the network
            global mac_ap
            mac_ap = pkt[Dot11].addr2


# find all STAs connected with target SSID
def find_STA(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        dot11_layer = pkt.getlayer(Dot11)
        # compare MAC with target
        if dot11_layer.addr3 == mac_ap:
            # find devices and add to list
            mac_sta = dot11_layer.addr2
            if mac_sta and (mac_sta not in devices):
                devices.add(mac_sta)


if __name__ == "__main__":
    print("Finding target SSID MAC address...")
    sniff(prn=find_network, iface=interface, timeout=t_out)
    print("MAC target AP :", mac_ap)

    print("Sniffing stations...")
    sniff(prn=find_STA, iface=interface, timeout=60)
    print(devices)
