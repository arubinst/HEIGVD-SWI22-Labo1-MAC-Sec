# Authors : Delphine Scherler & Wenes Limem
# Date : 31.03.2022
# Description : Script capable de révéler le SSID correspondant à un réseau configuré comme étant "invisible".

# Remarque : Pour l'instant le script détecte les réseaux cachés, mais il manque la révélation du SSID

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, Dot11ProbeReq

bssid = ""
probes = {}


# find probes
def find_probes(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        # extract the MAC address of the network
        essid = pkt[Dot11Elt].info
        # get the name of it
        ssid = pkt[Dot11Elt].info.decode()
        # extract network stats
        stats = pkt[Dot11ProbeReq].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # add probe to the list
        if essid not in probes:
            probes[essid] = [essid, ssid, channel, pkt.info]


# method to find hidden Wifi
def hidden_ap_discovery(pkt):
    if pkt.haslayer(Dot11Beacon):
        # if packet does not show SSID
        if '\x00' in pkt[Dot11Elt].info.decode():
            bssid = pkt.addr2
            print("Hidden Wifi detected! BSSID: " + bssid)


if __name__ == "__main__":
    interface = "wlan0"
    t_out = 5
    print("sniffing for hidden wifi during " + str(t_out) + " seconds")
    sniff(iface=interface, prn=hidden_ap_discovery, timeout=t_out)
    sniff(iface=interface, prn=find_probes, timeout=t_out)
    print("done sniffing ...\n")

    print(probes)




