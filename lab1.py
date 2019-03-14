import socket
import os
import sys
import time
import select
import struct
maxhops = 3
timeout = 1
def checksum_function(string):
	result = 0
	length = len(string)
	print (length)
	n = length % 2
	for i in range(0, length - n, 2):
		result += ord(string[i]) + (ord(string[i+1]) << 8)
	if length % 2 != 0:
		result += ord(string[-1])
	while (result >> 16):
		result = (result & 0xffff) + (result >> 16)
	result = ~result & 0xffff
	print ("*****",result)
	return result

for ttl in range(1,maxhops):	
	address = socket.gethostbyname(sys.argv[1])
	current_proto = socket.getprotobyname("ICMP")
	
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, current_proto)
	sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
	sock.settimeout(timeout)

	pid = os.getpid()
	
	ip_address = []
	trip_time = []
	for j in range(3):
		packet = struct.pack("!BBHHH", 8, 0, 0, pid, ttl*3+j)
		data = struct.pack("c"*56,"0"*56)
		checksum = socket.htons(checksum_function(packet))
		packet = struct.pack("!BBHHH", 8, 0, checksum, pid, ttl*3+j)
		sock.sendto(packet, (address, 0))
		
		start_time = time.time()
		while (True):
			receive = select.select([sock],[],[],0)
			if receive[0]:
				rtt = time.time() - start_time
				receive_packet, (ip,port) = sock.recvfrom(1024)
				icmpHeader=receive_packet[20:28]
				type_,code,checksum,packetID,sequence=struct.unpack("bbHHh",icmpHeader) 
				if sequence == ttl*3+j:
					ip_address.append(ip)
					trip_time.append(rtt)
			if time.time() - start_time > timeout:
				ip_address.append("*")
				trip_time.append(0)
				break

	for j in range(3):
		if ip_address[j] == "*":
			print ('*')
		else:
			print (ip_address[j],trip_time[j])				
		



		
		
			
		
	
	
	


	


	
	
	

	


	
	
	

	
	
	

