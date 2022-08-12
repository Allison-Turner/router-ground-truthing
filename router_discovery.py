#! /usr/bin/env python3

import sys, time, argparse
from multiprocessing import Process

# The following line will import all Scapy modules
from scapy.all import *
from getmac import get_mac_address


DESCRIPTION = """
Router discovery tool
"""
parser = argparse.ArgumentParser(description=DESCRIPTION, formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-f', '--frequency', dest='freq', help='Interval in seconds between solicitation packet emissions', default='10', type=int)
parser.add_argument('-i', '--ip-version', dest='ip_version', help='', choices=['IPv4', 'IPv6', 'dual'], default='dual')
parser.add_argument('-t', '--timestamp', dest='timestamp', help='', required=True)
parser.add_argument('-p', '--pcap-dir', dest='pcap_dir', help='', default='./pcaps/')
parser.add_argument('-o', '--output-dir', dest='output_dir', help='', default='./logs/')
parser.add_argument('-r', '--repetitions', dest='repetitions', help='', default='1', type=int)

args = parser.parse_args()


def arp_router_discovery(timeout_secs, outfile):
	try:
		logfile = open(outfile, 'a')
		sys.stdout = logfile
		sys.stderr = logfile
		print("----------------------------------------------------------------------------------------------------")
		print("\n" + time.ctime() + "\n")
		ans, unans = arping("192.168.1.0/24", timeout=timeout_secs, verbose=0)
		print("Answers:\n" + str(ans.summary()))
		print("Unanswered Packets:\n" + str(unans.summary()))
		print("----------------------------------------------------------------------------------------------------")
    	
	finally:
		sys.stdout.close()
		sys.stdout = sys.__stdout__

		sys.stderr.close()
		sys.stderr = sys.__stderr__


def ndp_router_discovery(timeout_secs, outfile):
	try:
		logfile = open(outfile, 'a')
		sys.stdout = logfile
		sys.stderr = logfile
		print("----------------------------------------------------------------------------------------------------")
		print("\n" + time.ctime() + "\n")

		ip_layer = IPv6(dst='ff02::2')
		router_solicitation = ICMPv6ND_RS()
		src_ll_addr = ICMPv6NDOptSrcLLAddr(lladdr=get_mac_address())
		packet = ip_layer / router_solicitation / src_ll_addr

		replies = sr1(packet, timeout=timeout_secs, verbose=0)
		print("Replies:\n" + str(replies))
		print("----------------------------------------------------------------------------------------------------")

	finally:
		sys.stdout.close()
		sys.stdout = sys.__stdout__

		sys.stderr.close()
		sys.stderr = sys.__stderr__
	


def run():
	arp_file = args.output_dir + "arp-" + args.timestamp + ".log"
	ndp_file = args.output_dir + "ndp-" + args.timestamp + ".log"

	if (args.ip_version == 'IPv4'):
		print("ARP Only")
		arp_router_discovery(args.freq, arp_file)

	elif (args.ip_version == 'IPv6'):
		print("NDP Only")
		ndp_router_discovery(args.freq, ndp_file)

	elif (args.ip_version == 'dual'):
		print("Parallel ARP+NDP")

		pARP = Process(
    		target = arp_router_discovery,
    		args = [args.freq, arp_file],
  			)

		pNDP = Process(
    		target = ndp_router_discovery,
    		args = [args.freq, ndp_file],
  			)

		pARP.start()
		pNDP.start()
		pARP.join()
		pNDP.join()

		if pARP.exitcode != 0:
			raise Exception('ARP loop exit code is nonzero: %i' % pARP.exitcode)

		if pNDP.exitcode != 0:
			raise Exception('NDP loop exit code is nonzero: %i' % pNDP.exitcode)


def main():
	for i in range(args.repetitions):
		run()


if __name__ == '__main__':
    main()