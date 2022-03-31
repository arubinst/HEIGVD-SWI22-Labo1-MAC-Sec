#!/usr/bin/python3
from scapy.all import *
from threading import Thread
import argparse
import pandas
from time import sleep
import os

# global variables
hashs = set() # stores already printed sta_mac and ap_mac

# here the packets are analyzed
def callback(packet):
    # (Re)AssoReq = STA is connected/connecting to the AP with the given MAC
    if packet.haslayer(Dot11QoS) and packet['Dot11FCS'].subtype == 12: # QoS null function always sent by client
        sta_mac = packet.addr1
        ap_mac = packet.addr2
        h = sta_mac + ap_mac
        if h not in hashs: # print only once
            hashs.add(h)
            print(f"{sta_mac}   {ap_mac}") # not pretty code but it works :/


def change_channel():
    ch = 1
    while not stop_signal:
        os.system(f"iwconfig {interface} channel {ch}")
        ch = ch % 13 + 1
        time.sleep(0.5)
    print("Stopped changing channel")


def sniff_sta():
    sniff(prn=callback, iface=interface, stop_filter=lambda _:stop_signal)
    print("Stopped sniffing")


if __name__ == "__main__":

    # check admin privileges
    if not os.getuid() == 0:
        print("Permission denied. Try running this script with sudo.")
        exit()

    # parse arguments
    parser = argparse.ArgumentParser(
        description="Listens for every STA sending probe requests",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
        
    parser.add_argument("interface", help="Interface to use")
    args = parser.parse_args()
    interface = args.interface


    stop_signal = False
    
    # Start channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    
    # Start sniffing
    print("Press any key to stop the script")
    print("Client              AP")
    sniffer = Thread(target=sniff_sta)
    sniffer.daemon = True
    sniffer.start()
    
    # Wait for the user input to stop the threads
    input()
    
    print("Stopping...")
    # wait for threads to finish
    stop_signal = True
    sniffer.join()
    channel_changer.join()
