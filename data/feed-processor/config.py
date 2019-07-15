from ConfigParser import ConfigParser
import os

def settings(section):
	dict1 = {}
	Config = ConfigParser()
	root_dir = os.path.dirname(os.path.realpath(__file__))
	Config.read(os.path.join(root_dir, 'config.ini'))
	options = Config.options(section)
	for option in options:
		try:
			tmp = Config.get(section, option)
			if tmp == 'True' or tmp == 'False':
				dict1[option] = Config.getboolean(section, option)
			elif ',' in tmp:
				dict1[option] = tmp.split(',')
			elif tmp == '':
				dict1[option] = None

			else:
				dict1[option] = tmp

			if dict1[option] == -1:
				DebugPrint("skip: %s" % option)
		except:
			print("exception on %s!" % option)
			dict1[option] = None
	return dict1