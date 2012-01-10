from unpacker import *

class UnDNS (Unpacker):

	def __init__(self):
		Unpacker.__init__(self)
		self.__TYPES = ['A','NS','MD','MF','CNAME','SOA','MB','MG','MR','NULL','WKS','PTR','HINFO','MINFO','MX','TXT']
		self.__QTYPES = ['AXFR', 'MAILB', 'MAILA', '*']
		self.__CLASSES = ['IN','CS','CH','HS']

	def __str__(self): 
		return "DNS unpacker"

	def __ttlToString(self, secs):
		hours, secs = divmod(secs, 3600)
		minutes, secs = divmod(secs, 60)
		response = []
		response += ["{0} hours".format(hours)] if hours>0 else ""
		response += ["{0} minutes".format(minutes)] if minutes>0 else ""
		response += ["{0} seconds".format(secs)] if secs>0 else ""
		return ", ".join(response) if len(response)>0 else "None"

	def __getDomainString(self, idx, p):
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
		
		idx = ptr+2 if ptr>0 else idx+1
		domain = ".".join(subdomains)
		return (idx, domain)

	def __getResourceRecord(self, idx, p):
		idx, RRname = self.__getDomainString(idx, p)
		RRtype = socket.ntohs(struct.unpack('H',p[idx:idx+2])[0])
		RRclass = socket.ntohs(struct.unpack('H',p[idx+2:idx+4])[0])
		RRttl = socket.ntohl(struct.unpack('I',p[idx+4:idx+8])[0])
		RRdatalen = socket.ntohs(struct.unpack('H',p[idx+8:idx+10])[0])
		idx += 10
		RRdata = p[idx:idx+RRdatalen]
		idx += RRdatalen

		if RRtype == 1:
			RRdata = socket.inet_ntoa(RRdata)

		RRtype = self.__TYPES[RRtype-1]
		RRclass = self.__CLASSES[RRclass-1]
		RRttl = self.__ttlToString(RRttl)
		RR = { 'type': RRtype, 'class': RRclass, 'ttl': RRttl, 'data': RRdata }
		return (idx, RR)

	def __getQuestionRecord(self, idx, p):
		idx, domain = self.__getDomainString(12, p)
		qtype = socket.ntohs(struct.unpack('H',p[idx:idx+2])[0])
		qtype = self.__TYPES[qtype-1] if qtype<252 else self.__QTYPES[qtype-252]
		qclass = socket.ntohs(struct.unpack('H',p[idx+2:idx+4])[0])
		qclass = self.__CLASSES[qclass-1] if qclass<>255 else "*"
		idx += 4
		question = { 'domain': domain, 'type': qtype, 'class': qclass }
		return (idx, question)

	def validate(self, packet):
		return (packet['udp']['dst'] == 53) or (packet['udp']['src'] == 53)

	def process(self, packet):
		p = packet['payload']
		d={}
		d['transaction-id'] = socket.ntohs(struct.unpack('H',p[0:2])[0])
		d['flags'] = socket.ntohs(struct.unpack('H',p[2:4])[0])

		questionRRs = socket.ntohs(struct.unpack('H',p[4:6])[0])
		answerRRs = socket.ntohs(struct.unpack('H',p[6:8])[0])
		authorityRRs = socket.ntohs(struct.unpack('H',p[8:10])[0])
		additionalRRs = socket.ntohs(struct.unpack('H',p[10:12])[0])

		d['questions'] = []
		for i in range(questionRRs):
			idx, question = self.__getQuestionRecord(12, p)
			d['questions'] += [question]

		d['answers'] = []
		for i in range(answerRRs):
			idx, rr = self.__getResourceRecord(idx, p)
			d['answers'] += [rr]			 			

		d['authority'] = []
		for i in range(authorityRRs):
			idx, rr = self.__getResourceRecord(idx, p)
			d['authority'] += [rr]			 			

		d['additional'] = []
		for i in range(additionalRRs):
			idx, rr = self.__getResourceRecord(idx, p)
			d['additional'] += [rr]			 			
	
		packet['top'] = "dns"
		packet['path'] += ".dns"
		packet['dns'] = d
		packet['payload'] = None

	def close(self):
		Unpacker.close(self)
