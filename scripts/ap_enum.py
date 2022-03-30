#!/usr/bin/python3
from scapy.all import *
from threading import Thread
import argparse
import pandas
from time import sleep
import os

hashs = set()

def callback(packet):
    if packet.haslayer(Dot11ProbeReq):
            ssid = packet.info.decode('utf-8')
            sta = packet.addr2
            h = ssid + sta
            if h not in hashs:
                hashs.add(h)
                print(f"{packet.addr2}    {ssid.ljust(25)}    {packet.dBm_AntSignal}")
            
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
        description="Listens for every STA sending probe requests",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
        
    parser.add_argument("interface", help="Interface to use to create fake APs")
    args = parser.parse_args()
    interface = args.interface

    stop_signal = False    
        
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    
    print("Press any key to stop the script")
    print("MAC                  SSID                         dm_Signal")
    sniffer = Thread(target=sniff_sta)
    sniffer.daemon = True
    sniffer.start()
    
    
    input()
    
    print("Stopping...")
    # wait for threads to finish
    stop_signal = True
    sniffer.join()
    channel_changer.join()
