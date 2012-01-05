from unpacker import *

class UnEthernet (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)

	def __str__(self): 
		return "Ethernet unpacker"

	def validate(self, packet):
		return packet['payload'][26:28]!='\xAA\xAA'

	def process(self, packet):
		p = packet['payload']
		packet['top'] = "eth"
		packet['path'] += ".eth"
		packet['eth'] = {}
		packet['eth']['dst']=binascii.hexlify(p[0:6])
		packet['eth']['src']=binascii.hexlify(p[6:12])
		packet['eth']['protocol']=socket.ntohs(struct.unpack('H',p[12:14])[0])
		packet['payload'] = p[14:]
