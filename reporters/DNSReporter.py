from reporters.reporter import *

try: DNSReporter
except:
	class DNSReporter (Reporter):

		def __call__(self):
			return self

		def report(self, packet):
			if packet['dns']['type'] == "query":
				src = packet['ip']['src']
				for question in packet['dns']['questions']:
					print "{0} is asking the IP address of {1}".format(src,question['domain']) 
