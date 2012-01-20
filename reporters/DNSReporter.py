from reporters.reporter import *

try: DNSReporter
except:
	class DNSReporter (Reporter):

		def __call__(self):
			return self

		def _validate(self, packet):
			valid = False
			if Reporter._validate(self):
				valid = packet['dns']['type'] == "query"
			return valid

		def report(self, packet):
			if self._validate(packet):
				src = packet['ip']['src']
				for question in packet['dns']['questions']:
					print "{0} is asking the IP address of {1}".format(src,question['domain']) 
