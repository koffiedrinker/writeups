from scapy.all import *
from binascii import unhexlify
import re

pcap = PcapReader("output.pcap")
for packet in pcap:
	if packet[DNS].ancount > 0:
		for answer in packet[DNS].an:
			print "Answer: " + answer.rdata 
	else: # Query
		query = packet[DNSQR].qname
		p = re.match('([a-zA-Z0-9]+)\.gzpgs\..*', query)
		print("Query: " + p.group(1))
