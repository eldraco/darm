import re
from analyzer import *

AnHTTP_stUnknown = 0
AnHTTP_stRequest = 1
AnHTTP_stResponse = 2

AnHTTP_reRequestAction = r"^(GET|POST) .* HTTP/1.1$"
AnHTTP_reResponseAction = r"^HTTP/1.1 [0-9]{3}"

class AnHTTP (Analyzer):

	def __init__(self, thread):
		Analyzer.__init__(self, thread)
		self.__state = AnHTTP_stUnknown

		self.request = {}
		self.request['headers'] = {}

		self.response = {}
		self.response['headers'] = {}

	def __test(self, pattern, regstr):
		regex = re.compile(regstr)
		return False if regex.search(pattern) is None else True 

	def analyzeData(self):		
		line = self._readln()
		while not line is None:
			self.__analyzeLine(line)
			line = self._readln()

	def __analyzeLine(self, line):

		if self.__state == AnHTTP_stUnknown:		

			if self.__test(line, AnHTTP_reRequestAction):
				print "-------------\nREQUEST: {0}\n".format(line)
				self.__state = AnHTTP_stRequest 

			elif self.__test(line, AnHTTP_reResponseAction):
				print "-------------\nRESPONSE: {0}".format(line)
				self.__state = AnHTTP_stResponse 
				
		elif self.__state == AnHTTP_stRequest:
			
			if line!="":
				cpos = line.find(":")
				if cpos>0:
					self.request['headers'][line[:cpos]] = line[cpos+1:].strip()
			else:
				#print self.request
				self.__state = AnHTTP_stUnknown

		elif self.__state == AnHTTP_stResponse:

			if line!="":
				cpos = line.find(":")
				if cpos>0:
					self.response['headers'][line[:cpos]] = line[cpos+1:].strip()
			else:
				headers = self.response['headers']
				#print "arrived to response end of line"
				if 'Content-Length' in headers:
					content_length = int(headers['Content-Length'])
					if content_length>0:
						self.response['content'] = self._read(content_length)
						print "Just read some content!:", self.response['content']
				#else:
				#	print "No content length in headers"
				#print self.response
				self.__state = AnHTTP_stUnknown
			
