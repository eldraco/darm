from reporters import *

try: GoogleReporter
except:
	class GoogleReporter (Reporter):

		def __call__(self):
			return self

		def __validate(self, request):
			valid = False
			if not request is None:
				if 'Host' in request['headers']:
					host = request['headers']['Host']
					if "google" in host.lower():
						valid = True
			return valid

		def report(self, src, dst, request, response):
			if self.__validate(request):
				params = request['url'].split("&")
				for param in params:
					if param.startswith("q="):
						query = self._urldecode(param[2:])
						print "{0} is googling '{1}'".format(src, query)
						break

GoogleReporter = GoogleReporter()
