import urllib

class Reporter:

	def _urldecode(self, str):
		return urllib.unquote(str).replace("+", " ")
