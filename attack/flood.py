from scapy.all import *
from scapy.layers.l2 import *
import time
url = "www.example.net"
SPOOF_ADDR = '192.168.56.101'
pkts = []
for x in range (10000,11000):		
	pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:0a")/IP(dst="192.168.56.101",src="192.168.56.1")/UDP()/DNS(qd=DNSQR(qname=url))
	pkts.append(pkt)

for pkt in pkts:
	sendp(pkt, verbose=0)
