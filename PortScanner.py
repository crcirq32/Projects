#!/usr/bin/python

#Do not use for illegal purposes
#Use at own risk
#Run with Python3

import optparse	
from socket import *
from threading import *

ScreenLock = Semaphore(value=1)		# Prevent other threads from preceeding

def ScanConnection(tgtHost, tgtPort):		# Start Function
	try:
		SockCon = socket(AF_INET, SOCK_STREAM)	#Start socket
		SockCon.connect((tgtHost, tgtPort))
		SockCon.send('')
		results=SockCon.recv(100)
		ScreenLock.acquire()		# Acquire the lock
		print ('[+] %d/tcp open'% tgtPort)
		print ('[+] ' + str(results))
	except:
		ScreenLock.acquire()
		print ('[-] %d/tcp closed '% tgtPort)
	finally:
		ScreenLock.release()
		SockCon.close()
		
def portScan(tgtHost, tgtPorts):	#begin function portscan
	try:
		tgtIP = gethostbyname(tgtHost)	#IP from domain name
	except:
		print ("[-] Cannot resolve '%s': Unknown host"%tgtHost)
		return
	try:
		tgtName = gethostbyaddr(tgtIP)	# Get hostname from IP
		print('\n[+] Scan Results for: ' +tgtName[0])
	except:
		print ('\n[+] Scan Results for: ' + tgtIP)
	setdefaulttimeout(1)
	for tgtPort in tgtPorts:	# Scan host and ports
		t = Thread(target=ScanConnection, args=(tgtHost, int(tgtPort)))
		t.start()

def main():
	parser = optparse.OptionParser('usage %prog -H'+' <target host> -p <target port>')
  #-H: specify Host IP
	parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
  #-p: specify port(s) (with commas)
	parser.add_option('-p', dest='tgtPort',type='string', help='specify target port[s] seperated by a comma')
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	tgtPorts = str(options.tgtPort).split(',')
  #start function to scan port and host
	if (tgtHost == None) | (tgtPorts[0] == None):
		print(parser.usage)
		exit(0)
	portScan(tgtHost, tgtPorts)
if __name__ == '__main__':
	main()
