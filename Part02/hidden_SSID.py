# Authors : Delphine Scherler & Wenes Limem
# Date : 31.03.2022
# Source : https://www.researchgate.net/publication/356557247_Discovering_Hidden_Wireless_Networks_leverazing_Python_Scapy
# Source : https://gist.github.com/dropmeaword/42636d180d52e52e2d8b6275e79484a0

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11


def hidden_ap_discovery(pkt):
    bssid=0
    if pkt.haslayer(Dot11Beacon):
        # if packet does not show SSID
        if not pkt.info:
            bssid = pkt.addr2
            print("Hidden Wifi detected ! BSSID: " + bssid)

    # if we found a hidden Wifi
    if bssid:
        # find probe requets with BSSID and display SSID
        if pkt.haslayer(Dot11):
            # subtype 4 = Probe Requests
            if pkt.type == 0 and pkt.subtype == 4:
                currentMac = pkt.addr2
                if currentMac == bssid:
                    print("SSID of hidden Wifi: " + pkt.info)


if __name__ == "__main__":
    interface = "wlan0"
    t_out=5
    sniff(iface=interface, prn=hidden_ap_discovery,timeout=5)
    print("done sniffing ...\n")
