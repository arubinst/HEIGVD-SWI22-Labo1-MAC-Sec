import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.eap import EAPOL

# dictionary that contains all the APs detected with their associated STAs
APs = dict()


def callback(packet):
    # if the packet is a beacon, we know it comes from an AP
    if packet.haslayer(Dot11Beacon):
        # we extract the BSSID from the frame
        bssid = packet[Dot11].addr3
        # even if a dictionary has unique keys we have to keep this if to avoid overwriting existent keys
        # with its associated values
        if bssid not in APs:
            ssid = packet[Dot11Elt].info.decode()
            APs[bssid] = {
                "SSID": ssid,
                "STA": set()  # associated stations
            }
    # else if the packet is a data frame and not a packet related to authentication frames
    elif packet.haslayer(Dot11) and packet.getlayer(Dot11).type == 2 and not packet.haslayer(EAPOL):
        source_mac = packet[Dot11].addr2
        destination_mac = packet[Dot11].addr1

        # we do not want broadcast address as source or destination MAC
        if source_mac == "ff:ff:ff:ff:ff:ff" or destination_mac == "ff:ff:ff:ff:ff:ff":
            return

        # if the source MAC belongs to an AP, the destination MAC belongs to a STA
        if source_mac in APs:
            APs[source_mac]["STA"].add(destination_mac)
        # else if the destination MAC belongs to an AP, the source MAC belongs to a STA
        elif destination_mac in APs:
            APs[destination_mac]["STA"].add(source_mac)


def change_channel(stop, iface):
    ch = 1
    while True:
        os.system(f"iwconfig {iface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

        if stop():
            break


def print_all(stop):
    while True:
        os.system("clear")
        print("BSSID             SSID")
        for MAC in APs:
            ssid = APs[MAC]["SSID"]
            print(f"{MAC} {ssid}")

            for STA in APs[MAC]["STA"]:
                print(f"\tAssociated STA : {STA}")

        print(f"Sniffing will end after {sniff_time} seconds...")
        time.sleep(0.5)

        if stop():
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A python script for sending fake channel beacons")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds), default is 20s",
                        default=20)
    args = parser.parse_args()

    interface = args.iface
    sniff_time = int(args.sniff_time)

    stop_threads = False
    # start the channel changer
    channel_changer = Thread(target=change_channel, args=(lambda: stop_threads, interface))
    channel_changer.daemon = True
    channel_changer.start()

    # start the thread that prints all the APs with their associated STAs
    printer = Thread(target=print_all, args=(lambda: stop_threads,))
    printer.daemon = True
    printer.start()

    sniff(prn=callback, iface=interface, timeout=sniff_time)

    stop_threads = True
    printer.join()
    channel_changer.join()
