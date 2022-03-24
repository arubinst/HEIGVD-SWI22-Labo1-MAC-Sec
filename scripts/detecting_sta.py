import argparse
import os
import time
from threading import Thread
import pandas as pandas
from scapy.layers.dot11 import Dot11ProbeReq, Dot11, Dot11Elt
from scapy.sendrecv import sniff

probes = pandas.DataFrame(columns=["Source MAC", "SSID of AP", "Channel"])
# set the index source MAC (MAC address of the device searching for the given SSID)
probes.set_index("Source MAC", inplace=True)


def callback(packet):
    if packet.haslayer(Dot11ProbeReq) and packet[Dot11Elt].info.decode() == chosen_ssid:
        # get the name of the network
        ssid = packet[Dot11Elt].info.decode()
        # source address (MAC) of the device searching for the given SSID
        source_mac = packet[Dot11].addr2
        # extract network stats
        stats = packet[Dot11ProbeReq].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        probes.loc[source_mac] = (ssid, channel)


def print_all(stop):
    while True:
        os.system("clear")
        print(probes)
        print(f"Sniffing will end after {sniff_time} seconds...")
        time.sleep(0.5)

        if stop():
            break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A python script to search for STAs looking for a given SSID")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds), default is 20s",
                        default=20)
    # ssid is mandatory
    parser.add_argument("ssid", help="SSID to find in probe requests from STAs")

    args = parser.parse_args()

    interface = args.iface
    sniff_time = int(args.sniff_time)
    chosen_ssid = args.ssid

    stop_threads = False
    # start the thread that prints all the probe requests
    printer = Thread(target=print_all, args=(lambda: stop_threads,))
    printer.daemon = True
    printer.start()

    # start sniffing
    sniff(prn=callback, iface=interface, timeout=sniff_time)

    # stop thread used for printing probe requests
    stop_threads = True
    printer.join()

    if probes.empty:
        print("No probe requests detected")
