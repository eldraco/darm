import sys
import socket
try:
	import pcapy
except:
	print 'This script requires pcapy. (apt-get install python-pcapy)'
	sys.exit(-1)

class Source:
	__unpacker = []

	def __init__(self):
		self.__seq = 0
		self.dumpfile = None

	def setUnpacker(self, unpacker):
		self.__unpacker = unpacker

	def analyze_packet(self, header, data):
		self.__seq += 1
		if not data:
			return

		info = {}
		info['caplen'] = header.getcaplen()
		info['totallen'] = header.getlen()
		info['timestamp'] = header.getts()
		info['seq'] = self.__seq		

		packet = {}
		packet['top'] = 'raw'
		packet['path'] = 'raw'
		packet['raw'] = info
		packet['payload'] = data
		self.__unpacker.addPacket(packet)

	def runFromFile(self, filename):
		reader = None		
		try:
			reader = pcapy.open_offline(filename)
		except:
			print "Could not open file {0}.".format(filename)
			sys.exit(-1)
		else:
			self.__run(reader)			
		
	def runLive(self, interface):
		reader = None		
		try:
			reader = pcapy.open_live(interface, 1600, 0, 100)
		except:
			print "Invalid interface or insufficient permissions."
			sys.exit(-1)
		else:
			self.__run(reader)			

	def __run(self, reader):			
		dumper = None
		if not self.dumpfile is None:
			print "Dumping output to {0}".format(self.dumpfile)
			dumper = reader.dump_open(self.dumpfile)

		print "Press Ctrl+C to stop"
		packet_count = 0
		try:
			while 1:
				try:
					packet = reader.next()
				except socket.timeout:
					pass
				else:
					packet_count += 1
					apply(self.analyze_packet, packet)
					if not dumper is None:
						apply(dumper.dump, packet)
		except KeyboardInterrupt:
			pass

		del reader
		print "Stopped."
		print '%d packets analyzed' % packet_count
		self.__unpacker.close()

