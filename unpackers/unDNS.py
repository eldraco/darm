from unpacker import *

class UnDNS (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)
		self.__TYPES = ['A','NS','MD','MF','CNAME','SOA','MB','MG','MR','NULL','WKS','PTR','HINFO','MINFO','MX','TXT']
		self.__QTYPES = ['AXFR', 'MAILB', 'MAILA', '*']
		self.__CLASSES = ['IN','CS','CH','HS']

	def __str__(self): 
		return "DNS unpacker"

	def __translateTTL(self, secs):
		hours, secs = divmod(secs, 3600)
		minutes, secs = divmod(secs, 60)
		response = []
		response += ["{0} hours".format(hours)] if hours>0 else ""
		response += ["{0} minutes".format(minutes)] if minutes>0 else ""
		response += ["{0} seconds".format(secs)] if secs>0 else ""
		return ", ".join(response) if len(response)>0 else "None"

	def validate(self, packet):
		return (packet['udp']['dst'] == 53) or (packet['udp']['src'] == 53)

	def process(self, packet):
		p = packet['payload']
		d={}
		d['transaction-id'] = socket.ntohs(struct.unpack('H',p[0:2])[0])
		d['flags'] = socket.ntohs(struct.unpack('H',p[2:4])[0])

		questionRRs = socket.ntohs(struct.unpack('H',p[4:6])[0])
		answerRRs = socket.ntohs(struct.unpack('H',p[6:8])[0])
		authRRs = socket.ntohs(struct.unpack('H',p[8:10])[0])
		additionalRRs = socket.ntohs(struct.unpack('H',p[10:12])[0])

		idx = 12
		for i in range(questionRRs):
			# obtaining questions
			subdomains = []
			c = ord(p[idx])
			while c>0:
				idx += 1
				subdomains += [p[idx:idx+c]]
				idx += c	
				c = ord(p[idx])
			idx += 1
			domains = ".".join(subdomains)
			qtype = socket.ntohs(struct.unpack('H',p[idx:idx+2])[0])
			qtype = self.__TYPES[qtype-1] if qtype<252 else self.__QTYPES[qtype-252]
			qclass = socket.ntohs(struct.unpack('H',p[idx+2:idx+4])[0])
			qclass = self.__CLASSES[qclass-1] if qclass<>255 else "*"
			print "\nDNS question {0}/{1} : {2}".format(i+1, questionRRs, (domains, qtype, qclass))
			idx += 4

		for i in range(answerRRs):
			# obtaining answers
			subdomains = []
			c = ord(p[idx])
			ptr = 0
			while c>0:
				if c & 0xC0:
					if ptr==0:
						ptr = idx
					idx = socket.ntohs(struct.unpack('H',p[idx:idx+2])[0]) & 0x3FFF
					c = ord(p[idx])
				
				idx += 1
				subdomains += [p[idx:idx+c]]
				idx += c	
				c = ord(p[idx])
			
			if ptr>0:
				idx = ptr + 2
			else:			
				idx = idx + 1

			RRname = ".".join(subdomains)
			RRtype = socket.ntohs(struct.unpack('H',p[idx:idx+2])[0])
			RRtype = self.__TYPES[RRtype-1]
			RRclass = socket.ntohs(struct.unpack('H',p[idx+2:idx+4])[0])
			RRclass = self.__CLASSES[RRclass-1]
			RRttl = socket.ntohl(struct.unpack('I',p[idx+4:idx+8])[0])
			RRttl = self.__translateTTL(RRttl)
			RRdatalen = socket.ntohs(struct.unpack('H',p[idx+8:idx+10])[0])
			idx += 10
			RRdata = p[idx:idx+RRdatalen]
			idx += RRdatalen
			print "DNS answer {0}/{1} : {2}".format(i+1, answerRRs, (RRname, RRtype, RRclass, RRttl, RRdata) )
			 			
	
		packet['top'] = "dns"
		packet['path'] += ".dns"
		packet['dns'] = d
		packet['payload'] = None

	def close(self):
		Unpacker.close(self)
