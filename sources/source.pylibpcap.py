#from unpacker import *
import sys
try:
	import pcap
except:
	print 'This script requires libpcap for Python. (apt-get install python-libpcap)'
	sys.exit(-1)

class Source:
	__unpacker = []

	def __init__(self):
		self.__seq = 0
		self.dumpfile = None

	def setUnpacker(self, unpacker):
		self.__unpacker = unpacker

	def analyze_packet(self, pktlen, data, timestamp):
		self.__seq += 1
		if not data:
			return

		info = {}
		info['length'] = pktlen
		info['timestamp'] = timestamp
		info['seq'] = self.__seq		

		packet = {}
		packet['top'] = 'raw'
		packet['path'] = 'raw'
		packet['raw'] = info
		packet['payload'] = data

		self.__unpacker.addPacket(packet)

	def runFromFile(self, filename):
		po = pcap.pcapObject()
		try:
			po.open_offline(filename)
		except:
			print "Could not open file {0}.".format(filename)
			sys.exit(-1)
			
		if not self.dumpfile is None:
			print "Dumping output to {0}".format(self.dumpfile)
			po.dump_open(self.dumpfile)

		print "Press Ctrl+C to interrupt file analysis"
		try:
			packet_count = 0
			packet = po.next()
			while (not packet is None):
				packet_count += 1
				apply(self.analyze_packet, packet)
				packet = po.next()
		except KeyboardInterrupt:
			print "Analysis stopped."			

		po.close()
		print '%d packets analyzed' % packet_count
		self.__unpacker.close()
		
	def runLive(self, interface):
		po = pcap.pcapObject()
		try:
			po.open_live(interface, 1600, 0, 100)
		except:
			print "You don't have permission to capture on this device."
			sys.exit(-1)

		if not self.dumpfile is None:
			print "Dumping output to {0}".format(self.dumpfile)
			po.dump_open(self.dumpfile)

		print "Press Ctrl+C to stop capturing"
		try:
			while 1:
				po.dispatch(1, self.analyze_packet)
		except KeyboardInterrupt:
			pass

		po.close()
		print '%d packets received, %d packets dropped, %d packets dropped by interface' % po.stats()
		self.__unpacker.close()

