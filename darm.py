#! /usr/bin/env python
from unpackers import *
from sources import *
from common import *

class MainClass:

	def __init__(self):
		
		options = CommandLine().options
		source = Source()
		source.setUnpacker(Tree().getRoot())

		if 'dumpfile' in options:
			source.dumpfile = options['dumpfile']	

		if options['method'] == "file":
			print "Opening {0}".format(options['filename'])
			source.runFromFile(options['filename'])
		elif options['method'] == "live":
			print "Capturing live from {0}".format(options['interface'])
			source.runLive(options['interface'])

if __name__ == "__main__":
	MainClass()
