#!/usr/bin/python2.7
import socket
import dpkt
import sys
def main():
	receiving = {}
	sending ={}
	if(len(sys.argv)<2):
		print "error: need argument"
		sys.exit(1)
	filename=open(sys.argv[1])
	pcapReader = dpkt.pcap.Reader(filename)
	for __noUse, data in pcapReader:
	    try: 
		ethernetPackets = dpkt.ethernet.Ethernet(data)
	    except dpkt.dpkt.UnpackError or AttributeError: 
		continue
	    if(ethernetPackets.type == dpkt.ethernet.ETH_TYPE_IP):	#check that it is ip packet
		if(ethernetPackets.data.p == dpkt.ip.IP_PROTO_TCP):		#check that if it is tcp packet (ip protocol)
		    if(ethernetPackets.data.data.flags & dpkt.tcp.TH_SYN != 0):	#tcp_data
		        if(ethernetPackets.data.data.flags & dpkt.tcp.TH_ACK != 0):
		            if(socket.inet_ntoa(ethernetPackets.data.dst) not in sending):
		                sending[socket.inet_ntoa(ethernetPackets.data.dst)] = 0
		            sending[socket.inet_ntoa(ethernetPackets.data.dst)] = sending[socket.inet_ntoa(ethernetPackets.data.dst)]+1
		        else:
		            if(socket.inet_ntoa(ethernetPackets.data.src) not in receiving):	#byte_order to string in IPV4 dotted-decimal notation
		                receiving[socket.inet_ntoa(ethernetPackets.data.src)] = 0
		            receiving[socket.inet_ntoa(ethernetPackets.data.src)] =receiving[socket.inet_ntoa(ethernetPackets.data.src)]+ 1
	for ip_address in receiving:
	    if(ip_address not in sending):
		sending[ip_address] = 0
	    if(receiving[ip_address] > sending[ip_address] * 3):
		print ip_address
	filename.close()
if __name__== '__main__':
	main()
