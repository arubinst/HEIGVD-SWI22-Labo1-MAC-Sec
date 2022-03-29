import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11

# source code : https://www.youtube.com/watch?v=_OpmfE43AiQ
# contains all the hidden SSID
hidden_ssid_aps = set()


# scan network on all channel
def change_channel(stop):
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

        if stop():
            break


def callback(pkt):
    if pkt.haslayer(Dot11Beacon):
        # get SSID
        ssid = pkt[Dot11Elt].info.decode()
        # the name of a hidden SSID is replaced with \x00\
        if "\x00" in ssid and (pkt[Dot11].addr3 not in hidden_ssid_aps):
            hidden_ssid_aps.add(pkt[Dot11].addr3)
            print("HIDDEN SSID Network Found! BSSID: ", pkt[Dot11].addr3)
    # looking for a Probe Response to confirm the SSID
    elif pkt.haslayer(Dot11ProbeResp) and (pkt[Dot11].addr3 in hidden_ssid_aps):
        ssid = pkt[Dot11ProbeResp].info.decode("utf-8")
        print(f"HIDDEN SSID Uncovered! {ssid}({pkt[Dot11].addr3})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A python script for reveal hidden SSID")
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds), default is 10s",
                        default=10)
    parser.add_argument("--interval",
                        help="The sending frequency (in seconds) between two frames sent, default is 0.1s",
                        default=0.1)
    args = parser.parse_args()

    interface = args.iface
    sniff_time = int(args.sniff_time)
    interval = float(args.interval)

    stop_threads = False
    # start the channel changer
    channel_changer = Thread(target=change_channel, args=(lambda: stop_threads,))
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    sniff(prn=callback, iface=interface, timeout=sniff_time)

    # stop threads used for sniffing
    stop_threads = True
    channel_changer.join()
