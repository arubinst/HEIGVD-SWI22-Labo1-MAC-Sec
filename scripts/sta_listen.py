#!/usr/bin/python3
from scapy.all import *
import argparse


ssid = ''
sta = set()

def callback(packet):
    if packet.haslayer(Dot11ProbeReq) and packet.info.decode("utf-8") == ssid:
            addr = packet.addr2
            if not addr in sta:
                sta.add(addr)
                print("\t", mac2str(addr))

def main(args):
    print("STAs trying to connect to ", ssid)
    sniff(prn=callback, iface=interface)
    #packets=rdpcap('deauth.pcap')
    #for packet in packets:
    #    callback(packet)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Listens for every STA looking up for the given SSID",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
        
    parser.add_argument("ssid")
    parser.add_argument("interface", help="Interface to use to create fake APs")
    args = parser.parse_args()
    ssid = args.ssid # I don't know why it doesn't work if I put this in main()
    main(args)
