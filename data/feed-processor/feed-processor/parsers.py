import requests
from bs4 import BeautifulSoup
from item_processors import *
import sys

def feed_handler(url, source_type, username=None, password=None):
	if source_type == 'linefile':
		return LineFeed(url, username, password)
	elif source_type == 'rss':
		return RSSFeed(url, username, password)
	else:
		raise ValueError('[-] ERROR: source_type ' + str(source_type) + ' is not supported.')

def eiqjson_handler(item, output_type):
	if output_type == 'singleip':
		entities = singleip(item)
	elif output_type == 'singledomain':
		entities = singledomain(item)
	elif output_type == 'singlehash':
		entities = singlehash(item)
	elif output_type == 'singleuri':
		entities = singleurl(item)
	elif output_type.startswith('blocklist_de'):
		entities = blocklist_de(item, output_type)
	elif output_type.startswith('fidelis'):
		entities = fidelis(item, output_type)
	else:
		entities = getattr(sys.modules[__name__], output_type)(item)
	return entities

class FeedFile():
	def __init__(self, url, username=None, password=None):
		if username is None and password is None:
			self.r = requests.get(url, stream=True)
		else:
			self.r = requests.get(url, stream=True, auth=HTTPBasicAuth(username, password))

		if self.r.encoding is None:
			self.r.encoding = 'utf-8'

class LineFeed(FeedFile):
	def __iter__(self):
		return self.r.iter_lines()

class RSSFeed(FeedFile):
	def __init__(self, url, username=None, password=None):
		FeedFile.__init__(self, url, username, password)
		self.bs4 = BeautifulSoup(self.r.content, 'html.parser')

	def __iter__(self):
		return self.bs4.findAll('item').__iter__()