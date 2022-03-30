# Authors : Delphine Scherler & Wenes Limem
# Date : 31.03.2022

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11ProbeReq

probes = {}
ap_list = {}


# Find probes
def find_probes(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        # extract the MAC address of the network
        essid = pkt[Dot11Elt].info
        # get the name of it
        ssid = pkt[Dot11Elt].info.decode()
        # extract address of the STA
        source = pkt[Dot11].addr2
        # extract network stats
        stats = pkt[Dot11ProbeReq].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # add probe to the list
        if essid not in probes:
            probes[essid] = [essid, ssidA, channel]


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
            ap_list[essid] = [essid, dbm_signal, channel]


# change the channel
def channel_hop(ch):
    new_ch = (ch + 6) % 14
    return new_ch


# generate_probeRq for the evil twin
def generate_probeRq(iface, ssid):
    sender_MAC = RandMAC()
    # 802.11 frame with subtype 04 as probe Request
    dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_MAC, addr3=sender_MAC)
    bc = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    pkt = RadioTap() / dot11 / bc / essid
    sendp(pkt, iface=iface, loop=2, inter=0.2)


if __name__ == "__main__":
    # fixing interface and timeout
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

    generate_probeRq(interface, tg_ssid)

    sniff(prn=find_probes, iface=interface, timeout=int(t_out))

    #print("probes scanned:")
    #for i in probes:
        #cnt += 1
        #print(cnt, probes.get(i))
