#! /usr/bin/python
from geoip import geolite2
#import win_inet_pton
import dpkt
import socket
import netifaces as ni
import optparse
THRESH = 5000

def findDownload(pcap):
	for (ts, buf) in pcap:
		try:
			eth = dpkt.ethernet.Ethernet(buf)
			ip = eth.data
			src = socket.inet_ntoa(ip.src)
			tcp = ip.data
			http = dpkt.http.Request(tcp.data)
			if http.method == 'GET':
				uri = http.uri.lower()
				if '.jar' in uri and 'javaloic' in uri:
					print '[!] ' + src + ' Downloaded LOIC.'
		except:
			pass


def findAttack(pcap):
	pktCount = {}
	for (ts, buf2) in pcap:
		try:
			eth = dpkt.ethernet.Ethernet(buf2)
			ip = eth.data
			src = socket.inet_ntoa(ip.src)
			dst = socket.inet_ntoa(ip.dst)
			tcp = ip.data
			dport = tcp.dport
			if dport == 80:
				stream = src + ':' + dst
				if pktCount.has_key(stream):
					pktCount[stream] = pktCount[stream] + 1
				else:
					pktCount[stream] = 1
		except:
			pass
	for stream in pktCount:
		pktsSent = pktCount[stream]
		if pktsSent > THRESH:
			src = stream.split(':')[0]
			dst = stream.split(':')[1]
			print '[+] '+src+' attacked '+dst+' with ' + str(pktsSent) + ' pkts.'


def main():
	parser = optparse.OptionParser('usage%prog -p <pcap file>')
	parser.add_option('-p', dest='pcapFile', type='string',\
	help='specify pcap filename')
	(options, args) = parser.parse_args()
	if options.pcapFile == None:
		print parser.usage
		exit(0)
	pcapFile = options.pcapFile
	f = open(pcapFile)
	pcap = dpkt.pcap.Reader(f)
	findDownload(pcap)
	f1 = open(pcapFile)
	pcap1 = dpkt.pcap.Reader(f1)
	findAttack(pcap1)
	
if __name__ == '__main__':
	main()