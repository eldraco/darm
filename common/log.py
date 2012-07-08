from common import *

class Log:

	def __call__(self):
		return self

	def __init__(self):
		pass

	def write(self, msg, verbosity=1):
		if verbosity <= CommandLine().cfg['verbosity']:
			print "{0}".format(msg)

Log = Log()
