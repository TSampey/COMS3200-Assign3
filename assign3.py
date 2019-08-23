import struct
import socket
import sys
import ipaddress
import threading
import os

class client:
	"""
	Responsible for keeping track of the clients information
	"""
	def __init__(self, ip_address, ll_address):
		"""
		Initialises all variables needed
		Constructor: __init___(self, ip_address, ll_address)
		"""
		self.ip_address = ip_address
		self.ip_no_mask = ip_address.split("/")[0]
		self.ll_address = ll_address
		self.gateway = None
		self.arpTable = {} #dictionary
		self.MTU = 1500
		self.id_counter = 0

	def get_idCounter(self):
		"""
		get_idCounter(None) -> (Int)
		Returns the current packet counter
		"""
		return self.id_counter
	
	def set_idCounter(self, value):
		"""
		set_idCounter(value)
		sets the packet id counter
		"""
		self.id_counter = value

	def get_ip(self):
		"""
		get_ip(None) -> (string)
		Gets the ip address without CIDR suffix
		"""
		return self.ip_no_mask
	
	def get_MTU(self):
		"""
		get_MTU(None) -> (Int)
		Returns the Maximum Transmission Unit 
		"""
		return self.MTU
	
	def set_MTU(self, value):
		"""
		set_MTU(None)
		Sets the Maximum Transmission Unit for the network
		"""
		self.MTU = value

	def get_llAddr(self):
		"""
		get_llAddr(None) -> (Int)
		"""
		return self.ll_address

	#adds to the arp table	
	def addToArpTable(self, ip_address, ll_address):
		"""
		addToArpTable(ip_address, linklayer_address) 
		Adds to ARP Table 
		"""
		self.arpTable[ip_address] = ll_address
	
	def viewArpTable(self):
		"""
		viewArpTable(None)

		Prints all entries within ARP table
		"""
		for key, value in self.arpTable.items():
			print("Key: ", key, " Value: ", value)
	
	def setGateway(self, ipaddress):
		""" 
		setGateway(ipaddress)
		Sets the Gateway IP Address
		"""
		self.gateway = ipaddress


	def getGateway(self):
		"""
		getGateway(None) -> (String)
		Returns the Gateway IP address : None if not set
		"""
		return self.gateway

	def hasGateway(self):
		"""
		hasGateway(None) -> (Boolean)
		Checks to see if Gateway has been set
		Returns True if set else False 
		"""
		if self.gateway == None:
			return False
		else:
			return True

	def hasMapping(self, ipaddr):
		"""
		hasMapping(ipaddr) -> (Boolean)
		Checks to see if an IP address has a mapping to a Link Layer Address
		Returns True if set else False

		"""
		
		if ipaddr in self.arpTable:
			if self.arpTable.get(ipaddr) != None: 
				return True
		return False		
			
	
	def get_link_layer_addr(self, ipaddress):
		"""
		get_link_layer_addr(ipaddress) -> (Int)
		Returns Link layer address mapped to an IP address
		"""
		return self.arpTable.get(ipaddress)


	def hasArpEntry(self, ipaddress):
		"""
		hasArpEntry(ipaddress) -> (Boolean)
		Checks to see if an IP address has a mapping to a Link Layer Address
		Returns True if set else False

		Prints to console if 'No Arp entry found' if ARP table doesnt have a mapping
	
		"""
		if self.arpTable.get(ipaddress) != None:
			return True
		else:
			print("No ARP entry found")
			return False
	
	def get_subnetId(self, CIDR_ipaddress):
		"""
		get_subnetId(CIDR_ipaddress) -> (IPv4Interface)
		Returns Subnet ID
		"""
		return ipaddress.ip_interface(CIDR_ipaddress)
	
	def same_subnet(self, other_ip_address):
		"""
		same_subnet(other_ip_address) -> (Boolean)
		Compares two IP addresses to see if they are within the same subnet
		"""
		
		return ipaddress.IPv4Address(other_ip_address) >= ipaddress.ip_network(self.ip_address,strict=False).network_address and \
			ipaddress.IPv4Address(other_ip_address) <= ipaddress.ip_network(self.ip_address,strict=False).broadcast_address
		

		

class IPv4_packet:
	"""
	Responsible for dealing with the packet creation when sending packets
	to other clients
	"""
	def __init__(self, length, fid, flags, offset, src_ip, dst_ip, payload):
		"""
		Initialises all header information
		Constructor: ___init___(self, length, fid, flags, offset, src_ip, dst_ip, payload)
		"""
		self.version = 0b0100
		self.header_length = 0b0101 
		self.type_of_service = 0b00000000 
		
		self.total_length = length 
		
		self.identifier = fid
		self.flags = flags
		self.fragment_offset = offset
		self.time_to_live = 0b00100000
		self.protocol = 0b00000000
		self.header_checksum = int(format(0b00, '016b'))
		self.src_address = src_ip
		self.dest_address = dst_ip
		self.payload = payload.encode()

		self.version_hLength_tos = ((self.version << 4) + self.header_length) << 8 + self.type_of_service
		
		self.flags_fragoffset = (self.flags << 13) + self.fragment_offset
		
		self.ttl_prot = ((self.time_to_live << 8) + self.protocol) 
		

		self.ip_header = struct.pack('! 6H', self.version_hLength_tos, self.total_length, self.identifier,\
			self.flags_fragoffset, self.ttl_prot, self.header_checksum)
		
		#print(type(self.ip_header), " - ", type(self.src_address)," - ", type(self.dest_address)," - ", type(self.payload))

		self.packet = self.ip_header+self.src_address + self.dest_address + self.payload


	def getPacket(self):
		"""
		getPacket(None) -> (Packet)
		Returns the packet object
		"""
		return self.packet

	
	def __bytes__(self):
		"""
		__bytes__(None) -> (Bytes)
		Returns a bytes representation of the packet object
		"""
		return self.packet



def return_args(string):
	"""
	return_args(string) -> <List>
	separates the arguments and returns them as a list
	"""
	args = string.split(' ',maxsplit=2)
	if len(args) == 3:
		if args[0]=="msg":
			return (args[0].strip(),args[1].strip(),args[2],None) #msg ip data
		elif args[0] == "arp" and args[1] == "set":
			ip, port = args[2].split(" ")
			return(args[0].strip(),args[1].strip(), ip.strip(), port.strip())
		else:
			return (args[0].strip(),args[1].strip(), args[2].strip(),None)
	
	elif len(args) == 2:
		return (args[0].strip(" "),args[1].strip(" "),None,None)
	
	return (None,None,None,None)




def main():
	"""
	Main Function
	"""
	arp = client(str(sys.argv[1]),str(sys.argv[2]))
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(2)
	port = int(arp.get_llAddr())
	s.bind(('LOCALHOST',port))
	global terminate
	terminate = False;
	

	thr = threading.Thread(target=receive_data, args=(s,))
	thr.start()
	
	while True:
		#sys.stdout.flush()
		arg1 = arg2 = arg3 = arg4 = "-1"
		sys.stdout.write("> ")
		
		command = input()
		str(command)
		
		arg1,arg2,arg3,arg4 = return_args(command)
		

		if str(command) == "gw set " + str(arg3):
			arp.setGateway(str(arg3))

		elif str(command) == "gw get":
			gway = arp.getGateway()
			if gway == None:
				print("None")
			else:
				print(gway)	
		
		elif str(command) == "arp set "+str(arg3)+" "+str(arg4):
			arp.addToArpTable(str(arg3), int(arg4))
		
		elif str(command) == "arp get "+ str(arg3):
			ll_add = arp.get_link_layer_addr(str(arg3))
			if ll_add != None:
				print(ll_add)
			else:
				print("None")
				

		elif str(command) == 'msg '+ str(arg2) +' '+str(arg3):
			#see if ip is in same gateway
			dstn_ip = str(arg2)
			dstn_port = -1
			message = str(arg3)

			if arp.same_subnet(dstn_ip):
				
				if arp.hasMapping(dstn_ip):
					dstn_port = arp.get_link_layer_addr(dstn_ip)
					send_msg(s,arp,dstn_ip,dstn_port,message[1:-1]) 
				else:
					print("No ARP entry found")
			else:
				#send to gateway 
				#Check if gateway is set
				if arp.hasGateway():
					dstn_port = arp.get_link_layer_addr(arp.getGateway())
					send_msg(s,arp,dstn_ip,dstn_port,message[1:-1]) 
				else:
					print("No gateway found")


		elif str(command) == "mtu set "+ str(arg3):
			arp.set_MTU(int(arg3))

		elif str(command) == "mtu get":
			print(arp.get_MTU())

		
		elif str(command) == "exit":

			terminate = True

			break
		sys.stdout.flush()



#send message
def send_msg(s,arp_details, dest_ip,dest_port, msg):
	"""
	send_msg(socket, arp_details, dest_ip, dest_port, msg)
	Responsible for sending a packet to another client
	"""

	source_ip = socket.inet_aton(arp_details.get_ip())
	destination_ip = socket.inet_aton(dest_ip)

	payload_size = arp_details.get_MTU() - 20 #MTU - IP Header

	if len(msg) <= payload_size: 
		t = IPv4_packet(len(msg) + 20, arp_details.get_idCounter(), 0, 0, source_ip, destination_ip, msg)
		ipv4_packet = bytes(t)
		s.sendto(ipv4_packet,('LOCALHOST',dest_port))
	else:

		payload, payload_size = payloads_creator(arp_details, msg)
		offsets = calc_frag_offsets(payload_size, len(msg))
		
		for i in range(len(payload)): #amount of offsets
			if i != len(payload) - 1:
				
				#length, fid, flags, offset, src_ip, dst_ip, payload
				packet = IPv4_packet(len(payload[i]) + 20, arp_details.get_idCounter(), 0b001, offsets[i], source_ip, destination_ip, payload[i])
				bytes_packet = bytes(packet)
				s.sendto(bytes_packet,('LOCALHOST',dest_port))
				#print("i != offsets length: ", i)
			else:
				#print("i == offsets length: ", i)
				packet = IPv4_packet(len(payload[i]) + 20, arp_details.get_idCounter(), 0b000, offsets[i], source_ip, destination_ip, payload[i])
				bytes_packet = bytes(packet)
				s.sendto(bytes_packet,('LOCALHOST',dest_port))
					
					
	arp_details.set_idCounter(arp_details.get_idCounter() + 1)
		

	return

def payloads_creator(arp_details, message):
	"""
	payloads_creator(arp_details, message)
	Handles the creation of the payloads in respect to the
	Maximum Transmission Unit of the clients network
	"""
	payloads = []
	count = 0
	mtu = arp_details.get_MTU()
	payload_size = int((mtu - 20)/8) * 8 #divisible by 8


	#print("payload size: ",payload_size)
	
	#print(len(message))
	while count <= len(message):
		payloads.append(message[count:count + payload_size])
		count = count + payload_size

	#print(len(payloads))
	#print("payloads length: ",len(payloads))
	#print(payloads)


	return payloads, payload_size
	
def calc_frag_offsets(max_payload_size, msg_size):
	"""
	calc_frag_offests(max_payload_size, msg_size) -> <List>
	Creates a list of packet offsets for packet fragmentation
	"""
	#returns a list of offsets
	offsets = []

	if (msg_size) % (max_payload_size) == 0: # -20 because its only the data

		offset_amount = (msg_size / max_payload_size)
		
		for i in range(int(offset_amount - 1)):
			offset = (i*(max_payload_size)/8)
			offsets.append(int(offset))
	else:

		offset_amount = round((msg_size / (max_payload_size)+1))
		
		for i in range(offset_amount):

			offset = (i*(max_payload_size)/8)
			offsets.append(int(offset))
	return offsets

def receive_data(s):
	"""
	receive_data(s)
	Responsible for handling the receiving of data received 
	from other clients
	"""
	#print(threading.current_thread().name)
	packets = {}
	while True:
		try:
			data, addr = s.recvfrom(1500)
			
			packets, evaluate_flag = add_packet_to_dict(data, packets)
			if evaluate_flag == 1:

				evaluate_packets(packets)
				packets = {}
			
		except OSError as e: 

			if terminate == True:
				break

def add_packet_to_dict(data, packets_dict):
	"""
	add_packet_to_dict(data, packets_dict) -> (Dict, Int)
	Creates a dictionary with all packets / packet fragments
	received
	"""

	eval_flag = 0
	
	pLength, pid, flags_offset, protocol, source_ip = struct.unpack('! 2x 3H x B 2x 4s 4x ', data[:20]) 

	offset = flags_offset & 0x1FFF
	flags = flags_offset >> 13
	protocol = format(int(protocol), '#04x')
	source_ip = socket.inet_ntoa(bytes(source_ip))
	
	key = source_ip+" " +str(pid)

	if key in packets_dict:
		packets_dict[key].append(data)
		if flags == 0:
			eval_flag = 1
	else:
		packets_dict[key] = [data]
		if flags == 0:
			eval_flag = 1

	return packets_dict, eval_flag


def evaluate_packets(p_dict):
	"""
	evaluate_packets(p_dict)
	evaluates the packets within the dictionary
	and outputs the correct message depending on 
	protocol
	"""
	for key, value in p_dict.items(): #loop through dict items
		source_ip = -1 
		protocol = -1
		msg_list =[]
		msg = ""
		for v in value: # loop through each value at key
			
			pLength, pid, flags_offset, protocol, source_ip = struct.unpack('! 2x 3H x B 2x 4s 4x ', v[:20])
			offset = flags_offset & 0x1FFF
			flags = flags_offset >> 13	
			
			source_ip = socket.inet_ntoa(bytes(source_ip))
			msg = v[20:].decode()

			
			protocol = format(int(protocol), '#04x')
			msg_list.append(msg)

		
		msg = msg.join(msg_list)	
		
		if protocol == "0x00":
			print('\b\bMessage received from {}: "{}"'.format(source_ip, msg))
		else:
			print("\b\bMessage received from {} with protocol {}".format(source_ip, protocol))	
	print("> ", end='', flush=True)

	return



if __name__ == '__main__':
    main()