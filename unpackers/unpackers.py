from unpacker import *
from unEthernet import *
from unIP import *
from unTCP import *
from unUDP import *
from unDNS import *

class Unpackers:

	def __init__(self):

		# layer 5 (application)
		uDNS = UnDNS()

		# layer 4 (transport)
		uUDP = UnUDP()
		uUDP.addUnpacker(uDNS)
		
		uTCP = UnTCP()

		# layer 3 (network)		
		uIP = UnIP()
		uIP.addUnpacker(uTCP)
		uIP.addUnpacker(uUDP)

		# layer 2 (data link)
		# arp?

		# layer 1 (physical)
		uEthernet = UnEthernet()
		uEthernet.addUnpacker(uIP)

		root = Unpacker()
		root.addUnpacker(uEthernet)
		self.__root = root

	def getRoot(self):
		return self.__root
