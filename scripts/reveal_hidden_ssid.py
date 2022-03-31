import argparse
import pandas
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11

# inspired by : https://www.youtube.com/watch?v=_OpmfE43AiQ

# initialize the hidden networks dataframe that will contain all the hidden APs nearby
hidden_networks = pandas.DataFrame(columns=["BSSID", "Uncovered SSID", "Signal (dBm)", "Channel"])
# set the index BSSID (MAC address of the AP)
hidden_networks.set_index("BSSID", inplace=True)


def callback(packet):
    # if the packet is a beacon
    if packet.haslayer(Dot11Beacon):
        # get SSID
        ssid = str(packet[Dot11Elt].info.decode())
        # in case of a hidden network, the name of the real SSID is replaced with \x00\ in beacons
        # we also check if the BSSID of the AP is already in the dataframe to avoid overwriting an existent BSSID with
        # its associated values
        if ssid.startswith("\x00") and (str(packet[Dot11].addr3) not in hidden_networks.index):
            # extract the MAC address of the network
            bssid = packet[Dot11].addr3
            # to align values in the dataframe
            ssid = ""
            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            # extract network stats
            stats = packet[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")
            hidden_networks.loc[bssid] = (ssid, dbm_signal, channel)

    # looking for a Probe Response from an AP in the dataframe to confirm the SSID
    elif packet.haslayer(Dot11ProbeResp) and (str(packet[Dot11].addr3) in hidden_networks.index):
        ssid = packet[Dot11ProbeResp].info.decode()
        bssid = packet[Dot11].addr3
        hidden_networks.loc[bssid, 'Uncovered SSID'] = ssid
        print(f"HIDDEN SSID Uncovered! {ssid}({bssid})")


def print_all():
    while True:
        os.system("clear")
        print(hidden_networks)
        print(f"Sniffing will end after {sniff_time} seconds...")
        # 1.5s to have the time to see that a SSID has been uncovered
        time.sleep(1.5)


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A python script to reveal hidden SSID")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds), default is 60s",
                        default=60)
    args = parser.parse_args()

    interface = args.iface
    sniff_time = int(args.sniff_time)

    # start the thread that prints all the hidden networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()

    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    sniff(prn=callback, iface=interface, timeout=sniff_time)
