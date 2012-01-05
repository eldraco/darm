import sys
from common import *

class TCPLoom:
	
	def __init__(self):
		self.__threads = []
		self.__index = {}
		self.__fullCount = 0
		self.__currentCount = 0

	def __findThread(self, packet):		
		src_ip = packet['ip']['src']
		dst_ip = packet['ip']['dst']
		src_port = packet['tcp']['src']
		dst_port = packet['tcp']['dst']
		t1 = (src_ip, src_port, dst_ip, dst_port)
		try:
			idx = self.__index[t1]
			return self.__threads[idx]
		except:
#			print "Could not find thread for packet {0}".format(t1)
			return None
	
	def __openThread(self, packet):
		src_ip = packet['ip']['src']
		dst_ip = packet['ip']['dst']
		src_port = packet['tcp']['src']
		dst_port = packet['tcp']['dst']		
		t1 = (src_ip, src_port, dst_ip, dst_port)
		t2 = (dst_ip, dst_port, src_ip, src_port)

		idx = len(self.__threads)
		self.__index[t1] = idx		
		self.__index[t2] = idx		

		thread = {}
		thread['data'] = ""
		thread['src'] = "{0}({1})".format(src_ip, KnownPorts().tcp(src_port))
		thread['dst'] = "{0}({1})".format(dst_ip, KnownPorts().tcp(dst_port))
		thread['state'] = 'open'
		thread['size'] = 0		
		thread['seq'] = self.__fullCount		 
		self.__threads += [thread]

		self.__fullCount += 1
		self.__currentCount += 1
#		print "Thread #{0} opened".format(idx) 
		return thread		

	def __closeThread(self, thread, state):		
#		try:
			if thread['state'] == 'open':
				self.__saveThread(thread)
				thread['state'] = state		
				thread['data'] = ""
				self.__currentCount -= 1
#		except:
#			print "Error while closing thread! {0}".format(sys.exc_type)
#			print "Thread: {0}".format(thread)
#			sys.exit(-1)			
		
	def __appendToThread(self, thread, packet):
#		try:
			p = packet['payload']
			if len(p)>0:
				thread['data'] += p
				thread['size'] += len(p)
#		except:
#			print "Error while appending to thread! {0}".format(sys.exc_type)
#			print "Thread: {0}".format(thread)
#			print "Conflicting packet: {0}".format(packet)
#			sys.exit(-1)			

	def __saveThread(self, thread):
		if thread['size']>0:
			filename = "{0}-{1}.data".format(thread['src'], thread['dst'])
			Log.write("Saving thread #{0} as {1} ({2} bytes)".format(thread['seq'], filename, thread['size']), 2)
			fh = open(filename,"wb")
			fh.write(thread['data'])
			fh.close()
		else:
			Log.write("Discarding empty thread {0} {1}-{2}".format(thread['seq'], thread['src'], thread['dst']), 2)
		
	def addPacket(self, packet):
		thread = self.__findThread(packet)
		if thread is None:
			thread = self.__openThread(packet)

		flags = packet['tcp']['flags']
		self.__appendToThread(thread, packet)

		if "FA" in flags:
			self.__closeThread(thread, "closed")
			Log.write("Thread #{0} closed.".format(thread['seq']), 2)
		elif "R" in flags:
			self.__closeThread(thread, "resetted")
			Log.write("Thread #{0} resetted!".format(thread['seq']), 2)

	def close(self):
		for thread in self.__threads:
			self.__closeThread(thread, "interrupted")		
		self.__threads = None

