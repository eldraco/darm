
class Analyzer:

	def __init__(self, thread):
		self.__thread = thread
		self.__cursor = 0

	def _readUntil(self, pattern):
		data = self.__thread['data']
		pos = data.find(pattern, self.__cursor)
		if (pos<0):
			return None
		else:
			line = data[self.__cursor:pos]
			self.__cursor = pos+len(pattern)
			return line	

	def _readln(self):
		return self._readUntil("\x0D\x0A")

	def _read(self):
		data = self.__thread['data']
		c = self.__cursor
		self.__cursor = len(data)-1
		return data[c:]

	def _read(self, count):
		data = self.__thread['data']
		c = self.__cursor
		self.__cursor += count
		return data[c:count]
