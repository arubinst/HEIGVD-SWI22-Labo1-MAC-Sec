import argparse

from scapy.all import *
# Args parsing
from scapy.layers.dot11 import Dot11Beacon

parser = argparse.ArgumentParser(prog="Scapy Hidden SSID reveal",
                                 usage="hidden_ssid_reveal.py -i wlp2s0mon",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to use, needs to be set to monitor mode")

args = parser.parse_args()

hidden_ssid_aps = set()


def PacketHandler(p):
    """
    Detect hidden ssid by storing AP address sending beacon with no ssid and checking their probe response
    :param p: the packet to analyse
    """
    if (p.type == 0) and (p.subtype == 5) and (p.addr3 in hidden_ssid_aps):
        print("HIDDEN SSID Uncovered: {} {}".format(str(p.info), str(p.addr3)))
    elif p.haslayer(Dot11Beacon) and len(p.info.decode()) == 0:
        print("AP MAC {}".format(p.addr3))
        if p.addr3 not in hidden_ssid_aps:
            hidden_ssid_aps.add(p.addr3)
            print("HIDDEN BSSID: {}".format(p.addr3))


sniff(iface=args.Interface, prn=PacketHandler)
