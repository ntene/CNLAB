import socket
import os
import sys
import time
import select
import struct
maxhops = 64
timeout = 1
def checksum_function(string):
	result = 0
	length = len(string)
	#print (length)
	n = length % 2
	for i in range(0, length - n, 2):
		result += string[i] + (string[i+1] << 8)
	if length % 2 != 0:
		result += string[-1]
	while (result >> 16):
		result = (result & 0xffff) + (result >> 16)
	result = ~result & 0xffff
	result = result >> 8 | (result << 8 & 0xff00)
	#print ("*****",hex(result))
	return result

address = socket.gethostbyname(sys.argv[1])
current_proto = socket.getprotobyname("ICMP")
flag = 0
print ("traceroute to " + sys.argv[1] + " (" + address + "), 64 hops max")
for ttl in range(1,maxhops):	
	ip_address = []
	trip_time = []
	for j in range(3):
		sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, current_proto)
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
		sock.settimeout(timeout)

		pid = os.getpid() & 0xffff
		packet = struct.pack("BBHHH", 8, 0, 0, pid, ttl*3+j)
		checksum = socket.htons(checksum_function(packet))
		packet = struct.pack("BBHHH", 8, 0, checksum, pid, ttl*3+j)
		'''req_type,code,checksum,packetID,sequence=struct.unpack("bbHHh",packet)
		print ("&&&", sequence) '''
		sock.sendto(packet, (address, 0))
		
		start_time = time.time()
		while (True):
			receive = select.select([sock],[],[],0)
			if receive[0]:
				rtt = time.time() - start_time
				receive_packet, (ip,port) = sock.recvfrom(1024)
				icmpHeader=receive_packet[20:28]
				req_type,code,checksum,packetID,sequence=struct.unpack("bbHHH",icmpHeader)
				if req_type == 0:
					flag = 1
				if sequence == ttl*3+j:
					ip_address.append(ip)
					trip_time.append(round(rtt*1000,4))
					break
				seq_number = struct.unpack("h",receive_packet[54:56])[0]
				if seq_number == ttl*3+j:
					ip_address.append(ip)
					trip_time.append(round(rtt*1000,4))
					break
			if time.time() - start_time > timeout:
				ip_address.append("*")
				trip_time.append(0)
				break

	print (ttl, end = "\t")
	for j in range(3):
		if ip_address[j] == "*":
			print ('*', end = " ")
		elif j != 0 and ip_address[j] == ip_address[j-1]:
			print (str(trip_time[j]) + " ms", end = " ")
		else:
			print (ip_address[j] + "  " +  str(trip_time[j]) + " ms", end = " ")		
	print ("")	
	if flag:
		break	
	
