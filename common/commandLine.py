import sys
import itertools

try: CommandLine
except:
		class CommandLine:

			def __call__(self):
				return self

			def __init__(self):
				self.__showBanner()
				if len(sys.argv)<2:	self.__paramError("arguments are missing")
				if (len(sys.argv)%2)==0:	self.__paramError("invalid arguments")				
				try:
					self.__initcfg()
					args = self.__group(sys.argv[1:], 2)
					for arg in args:
						self.__setArgument(arg)
				except Exception as ex:
					self.__paramError("unhandled parsing error - {0}".format(ex))
				else:
					self.__checkMandatoryArgs()			

			def __showBanner(self):
				print "darm - intelligent network sniffer for the masses"

			def __initcfg(self):
				self.cfg = {}
				self.cfg['verbosity'] = 1

			def __group(self, lst, n):
				# by Brian Quinlan
				# http://code.activestate.com/recipes/303060-group-a-list-into-sequential-n-tuples/
				return itertools.izip(*[itertools.islice(lst, i, None, n) for i in range(n)])

			def __setArgument(self, arg):
				if arg[0]=="-i":
					if 'method' in self.cfg: self.__paramError("specify one input source only")
					self.cfg['method'] = 'live'
					self.cfg['interface'] = arg[1]

				elif arg[0]=="-r":
					if 'method' in self.cfg: self.__paramError("specify one input source only")
					self.cfg['method'] = 'file'
					self.cfg['filename'] = arg[1]

				elif arg[0]=="-w":
					self.cfg['dumpfile'] = arg[1]

				elif arg[0]=="-v":
					try:
						value = int(arg[1])
					except:
						self.__paramError("verbosity level must be a number")
					else:			
						if value<0 or value>2: self.__paramError("verbosity level must be between 0 and 2")
						print "Verbosity set to {0}".format(value)
						self.cfg['verbosity'] = value

				else:
					self.__paramError("parameter {0} not recognized".format(arg[0])) 

			def __checkMandatoryArgs(self):
				if not 'method' in self.cfg: self.__paramError("specify input method")

			def __paramError(self, msg):
				print "Invalid arguments: {0}".format(msg)
				print "USAGE:"
				print " METHOD: determines source of input data. Mandatory."
				print "  -i (interface)   live interface"
				print "  -r (filename)    capture file"
				print " OUTPUT: Dump input data to capture file."
				print "  -w (filename)    dump filename"
				print " VERBOSITY: how much detail you want about ongoing tasks. Must be between 0 and 2. Default is 1."
				print "  -v (level)       verbosity level number"
				sys.exit(-1)

CommandLine = CommandLine()
