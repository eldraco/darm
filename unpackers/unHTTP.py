from unpacker import *

class UnHTTP (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)

	def __str__(self): 
		return "HTTP unpacker"

	def validate(self, packet):
		return packet['ip']['protocol'] == socket.IPPROTO_TCP

	def process(self, packet):
		p = packet['payload']
		packet['top'] = "tcp"
		packet['path'] += ".tcp"
		packet['tcp'] = {}
		packet['tcp']['src'] = socket.ntohs(struct.unpack('H',p[0:2])[0])
		packet['tcp']['dst'] = socket.ntohs(struct.unpack('H',p[2:4])[0])
		packet['tcp']['flags'] = ord(p[13])
		
		dataOffset = (ord(p[12]) & 0xF0) >> 4
		packet['payload'] = p[dataOffset*4:]
