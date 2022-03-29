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
        # even if a dictionary has unique keys we have to keep this "if" to avoid overwriting existent keys
        # with their associated values
        if bssid not in APs:
            ssid = packet[Dot11Elt].info.decode()
            APs[bssid] = {
                "SSID": ssid,
                "STA": set()  # associated stations
            }
    # else if the packet is a data frame
    elif packet.haslayer(Dot11) and packet[Dot11].type == 2:
        source_mac = packet[Dot11].addr2
        destination_mac = packet[Dot11].addr1

        broadcast_mac = "ff:ff:ff:ff:ff:ff"

        # we do not want broadcast address as source or destination MAC
        if source_mac == broadcast_mac or destination_mac == broadcast_mac:
            return

        # if the source MAC belongs to an AP, the destination MAC belongs to a STA
        if source_mac in APs:
            APs[source_mac]["STA"].add(destination_mac)
        # else if the destination MAC belongs to an AP, the source MAC belongs to a STA
        elif destination_mac in APs:
            APs[destination_mac]["STA"].add(source_mac)


def change_channel(iface):
    ch = 1
    while True:
        os.system(f"iwconfig {iface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


def print_all():
    while True:
        os.system("clear")
        print("BSSID             SSID")
        for mac in APs:
            # printing the AP with its MAC address and SSID
            ssid = APs[mac]["SSID"]
            print(f"{mac} {ssid}")

            # printing STAs associated with the AP
            for sta in APs[mac]["STA"]:
                print(f"\tAssociated STA : {sta}")

        print(f"Sniffing will end after {sniff_time} seconds...")
        time.sleep(0.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A python script for detecting STAs associated with APs")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds), default is 20s",
                        default=20)
    args = parser.parse_args()

    interface = args.iface
    sniff_time = int(args.sniff_time)

    # start the channel changer
    channel_changer = Thread(target=change_channel, args=(lambda: interface,))
    channel_changer.daemon = True
    channel_changer.start()

    # start the thread that prints all the APs with their associated STAs
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()

    sniff(prn=callback, iface=interface, timeout=sniff_time)
