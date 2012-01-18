from reporters.reporter import *
from GoogleReporter import *

try: HTTPReporter
except:
	class HTTPReporter (Reporter):

		def __call__(self):
			return self

		def report(self, src, dst, request, response):
			GoogleReporter().report(src, dst, request, response)

HTTPReporter = HTTPReporter()
