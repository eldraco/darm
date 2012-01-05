from unpacker import *
from unEthernet import *
from unIP import *
from unTCP import *

class Tree:

	def __init__(self):

		uTCP = UnTCP()

		uIP = UnIP()
		uIP.addUnpacker(uTCP)

		uEthernet = UnEthernet()
		uEthernet.addUnpacker(uIP)

		root = Unpacker()
		root.addUnpacker(uEthernet)
		self.__root = root

	def getRoot(self):
		return self.__root
