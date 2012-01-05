#! /usr/bin/env python
from unpackers import *
from sources import *
from common import *

class darm:

	def __init__(self):
		cfg = CommandLine().cfg
		self.__source = Source()
		self.__source.setUnpacker(Tree().getRoot())

	def run(self):	
		cfg = CommandLine().cfg
		if 'dumpfile' in cfg:
			self.__source.dumpfile = cfg['dumpfile']	

		if cfg['method'] == "file":
			print "Opening {0}".format(cfg['filename'])
			self.__source.runFromFile(cfg['filename'])

		elif cfg['method'] == "live":
			print "Capturing live from {0}".format(cfg['interface'])
			self.__source.runLive(cfg['interface'])

if __name__ == "__main__":
	darm().run()