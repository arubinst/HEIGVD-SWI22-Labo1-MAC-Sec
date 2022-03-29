import argparse
import os
import time
from threading import Thread
import pandas as pandas
from scapy.layers.dot11 import Dot11ProbeReq, Dot11, Dot11Elt
from scapy.sendrecv import sniff

# initialize the probe requests dataframe that will contain all the probe requests detected
probes = pandas.DataFrame(columns=["Source MAC", "SSID of AP", "Channel"])
# set the index source MAC (MAC address of the device searching for the given SSID)
probes.set_index("Source MAC", inplace=True)


def callback(packet):
    # if the packet is a probe request and contains the chosen SSID
    if packet.haslayer(Dot11ProbeReq) and packet[Dot11Elt].info.decode() == chosen_ssid:
        # get the name of the network
        ssid = packet[Dot11Elt].info.decode()
        # source MAC address of the device searching for the given SSID
        source_mac = packet[Dot11].addr2
        # extract network stats
        stats = packet[Dot11ProbeReq].network_stats()
        # get the channel of the AP
        channel_in_probe = stats.get("channel")
        probes.loc[source_mac] = (ssid, channel_in_probe)


def print_all():
    while True:
        os.system("clear")
        print(probes)
        print(f"Sniffing will end after {sniff_time} seconds...")
        time.sleep(0.5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A python script to search for STAs looking for a given SSID")
    parser.add_argument("ssid", help="SSID to find in probe requests from STAs")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds), default is 20s",
                        default=20)

    args = parser.parse_args()

    interface = args.iface
    sniff_time = int(args.sniff_time)
    chosen_ssid = args.ssid

    # start the thread that prints all the probe requests
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()

    # start sniffing
    sniff(prn=callback, iface=interface, timeout=sniff_time)

    if probes.empty:
        print("No probe requests detected")
