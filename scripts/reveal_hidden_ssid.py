import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11

# inspired by : https://www.youtube.com/watch?v=_OpmfE43AiQ

# set that contains all the hidden SSID
hidden_ssid_aps = set()


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


def callback(packet):
    # if the packet is a beacon
    if packet.haslayer(Dot11Beacon):
        # get SSID
        ssid = str(packet[Dot11Elt].info.decode())
        # in a hidden network, the name of the real SSID is replaced with \x00\
        # we also check if the BSSID of the AP is already in the set to avoid overwriting an existent MAC address
        if ssid.startswith("\x00") and (packet[Dot11].addr3 not in hidden_ssid_aps):
            hidden_ssid_aps.add(packet[Dot11].addr3)
            print("HIDDEN SSID Network Found! BSSID: ", packet[Dot11].addr3)

    # looking for a Probe Response from an AP in the set to confirm the SSID
    elif packet.haslayer(Dot11ProbeResp) and (packet[Dot11].addr3 in hidden_ssid_aps):
        ssid = packet[Dot11ProbeResp].info.decode()
        print(f"HIDDEN SSID Uncovered! {ssid}({packet[Dot11].addr3})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A python script to reveal hidden SSID")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds), default is 20s",
                        default=20)
    parser.add_argument("--interval",
                        help="The sending frequency (in seconds) between two frames sent, default is 0.1s",
                        default=0.1)
    args = parser.parse_args()

    interface = args.iface
    sniff_time = int(args.sniff_time)
    interval = float(args.interval)

    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    sniff(prn=callback, iface=interface, timeout=sniff_time)
