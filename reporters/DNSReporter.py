from reporters.reporter import *
import time

try: DNSReporter
except:
	
	class DNSReporter (Reporter):

		def __init__(self):
			self.__domains = []

		def __call__(self):
			return self

		def _validate(self, packet):
			valid = False
			if Reporter._validate(self):
				valid = packet['dns']['type'] == "query"
			return valid

		def __addDomainRequestEntry(self, who, when, what):
			
			text = "({2}) {0} is asking the IP address of {1}".format(who,what,when)
			Log.write(text, 2)


		def report(self, packet):
			if self._validate(packet):
				src = packet['ip']['src']
				timestamp = packet['raw']['timestamp']
				for question in packet['dns']['questions']:
					
					ts = time.localtime(timestamp[0])
					timeAsString = time.asctime(ts)
					self.__addDomainRequestEntry(src, timeAsString, question['domain'])
					

		def summaryReport(self):
			return ""

	DNSReporter = DNSReporter()	