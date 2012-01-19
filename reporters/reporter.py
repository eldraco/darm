import urllib

class Reporter:

	def __init__(self):
		pass

	def _urldecode(self, str):
		return urllib.unquote(str).replace("+", " ")
