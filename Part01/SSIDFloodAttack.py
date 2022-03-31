from scapy.all import *
from threading import Thread
from faker import Faker
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap


def send_beacon(ssid, mac, infinite=True):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    # ESS+privacy to appear as secured on some devices
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap() / dot11 / beacon / essid
    sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)


if __name__ == "__main__":
    f = input("Do you want to use a file [Y|N]: ")
    if f.__eq__('Y') or f.__eq__('y'):
        iface = "wlan0"
        path_to_file = input("Path to file:")
        fl = open(path_to_file, "r")
        list_of_lines = []
        for line in fl:
            stripped_line = line.strip()
            line_list = stripped_line.split()
            list_of_lines.append(line_list)
        print("Generating beacons, names are based on input file ... \n")
        for i in list_of_lines:
            ssid = i[0] + i[1]
            mac = i[2]
            Thread(target=send_beacon, args=(ssid, mac)).start()
            print(ssid, mac)
    else:
        # number of access points
        n_ap = 5
        iface = "wlan0"
        # generate random SSIDs and MACs
        faker = Faker()
        print("Generating beacons, names are faked... \n")
        ssids_macs = [(faker.name(), faker.mac_address()) for i in range(n_ap)]
        for ssid, mac in ssids_macs:
            Thread(target=send_beacon, args=(ssid, mac)).start()
            print(ssid, mac)
