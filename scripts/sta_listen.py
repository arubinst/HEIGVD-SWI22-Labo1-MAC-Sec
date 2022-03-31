#!/usr/bin/python3
from scapy.all import *
import argparse
from threading import Thread
import os

def callback(packet):
    if packet.haslayer(Dot11ProbeReq) and packet.info.decode("utf-8") == ssid:
        addr = packet.addr2
        if not addr in sta:
            sta.add(addr)
            print("\t", addr)

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

    parser = argparse.ArgumentParser(
        description="Listens for every STA looking up for the given SSID",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
        
    parser.add_argument("ssid")
    parser.add_argument("interface", help="Interface to use to create fake APs")
    args = parser.parse_args()
    
    ssid = args.ssid
    interface = args.interface
    sta = set()
    stop_signal = False
    
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    
    print("Press any key to stop the script")
    print("STAs trying to connect to ", ssid)
    sniffer = Thread(target=sniff_sta)
    sniffer.daemon = True
    sniffer.start()
    
    input()
    
    print("Stopping...")
    # wait for threads to finish
    stop_signal = True
    sniffer.join()
    channel_changer.join()

