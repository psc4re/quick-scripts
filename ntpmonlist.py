#!/usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #suppress scapy warnings generated due to random UDP sport
#Requires module https://pypi.python.org/pypi/ntplib/
#Usage: ./ntpmonlist.py <<inputfile>> or just ./ntpmonlist.py
#Legend: pass: vulnerable, fail: safe
# @psc4re's quick ntp monlist vulnerability check script  
from scapy.all import *
import sys
if(len(sys.argv)) > 1:
    f = open(sys.argv[1],'r')
else:
    var = raw_input("Please enter the filename: ")
    f = open(var,'r')    
lines = f.readlines()
f.close()
for line in lines:
	line = line.strip('\n')
	try:
		#Generating the NTP v2 Monlist Packet and sending
		packet=sr1(IP(dst=str(line))/UDP(dport=123)/Raw(load=str("\x17\x00\x03\x2a")+ str("\00")*4),timeout=1)
		if len(packet) > 0:
			print packet.summary()
			print str(line)+": pass (vulnerable)"
	except:
		print str(line)+": fail"