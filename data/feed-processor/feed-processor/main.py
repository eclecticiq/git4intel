from parsers import feed_handler, eiqjson_handler
from pprint import pprint
import json
import os
import uuid
import time
from item_processors import set_ref_objects
import urlparse
import sys

MAX_FILE_SIZE = 2000000

feeds = [
	# ['https://openphish.com/feed.txt', 'linefile', 'singleurl'],
	# ['http://malc0de.com/rss/', 'rss', 'malc0de'],
	# ['http://osint.bambenekconsulting.com/feeds/c2-masterlist.txt', 'linefile', 'bambenek'],
	# ['https://lists.blocklist.de/lists/ftp.txt', 'linefile', 'blocklist_de_ftp'],
	# ['https://lists.blocklist.de/lists/apache.txt', 'linefile', 'blocklist_de_apache'],
	# ['https://lists.blocklist.de/lists/imap.txt', 'linefile', 'blocklist_de_imap'],
	# ['https://lists.blocklist.de/lists/ssh.txt', 'linefile', 'blocklist_de_ssh'],
	# ['https://lists.blocklist.de/lists/sip.txt', 'linefile', 'blocklist_de_sip'],
	['https://cti.redsocks.nl/customer/eclecticiq/', 'linefile', 'redsocks_something'],
	['https://lists.blocklist.de/lists/bruteforcelogin.txt', 'linefile', 'blocklist_de_brute'],
	['https://lists.blocklist.de/lists/bots.txt', 'linefile', 'blocklist_de_bots'],
	['https://lists.blocklist.de/lists/strongips.txt', 'linefile', 'blocklist_de_strongips'],
	['https://raw.githubusercontent.com/fideliscyber/indicators/master/master-hostnames.csv', 'linefile',
	 'fidelis_masterdomain'],
	['https://raw.githubusercontent.com/fideliscyber/indicators/master/master-hostnames.csv', 'linefile',
	 'fidelis_masterip'],
	['https://www.bleepingcomputer.com/feed/', 'rss', 'news'],
	['http://feeds.arstechnica.com/arstechnica/technology-lab?format=xml', 'rss', 'news'],
	['https://www.darkreading.com/rss_simple.asp', 'rss', 'news'],
	['https://krebsonsecurity.com/feed/', 'rss', 'news'],
	['https://nakedsecurity.sophos.com/feed/', 'rss', 'news'],
	['https://securelist.com/feed/', 'rss', 'news'],
	['http://www.zdnet.com/news/rss.xml', 'rss', 'news'],
	['http://feeds.feedburner.com/TheHackersNews?format=xml', 'rss', 'news'],
	['https://threatpost.com/feed/', 'rss', 'news'],
	# ['http://osint.bambenekconsulting.com/feeds/dga-feed-high.csv', 'linefile', 'bambenek_dga'],
	# ['http://cinsscore.com/list/ci-badguys.txt', 'linefile', 'singleip'],
	# ['https://lists.blocklist.de/lists/mail.txt', 'linefile', 'blocklist_de_ftp'],

]

def get_source_ref(source_string):
	return str(uuid.uuid5(uuid.NAMESPACE_DNS, source_string))[:8]

def get_time_ref():
	return str(time.strftime("-%Y%m%d-%H%M%S"))

def convert_feed(url, source_type, output_type, username=None, password=None):

	feed = feed_handler(url, source_type, username=username, password=password)
	set_ref_objects()
	bundle = {'entities': []}
	json_bundle = json.dumps(bundle)
	for item in feed:
		bundle['entities'] = bundle['entities'] + eiqjson_handler(item, output_type)
		# if len(bundle['entities']) > 0:
		# 	pprint(bundle)
		# 	sys.exit(0)
		json_bundle = json.dumps(bundle)
		if len(json_bundle) > MAX_FILE_SIZE:
			with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'out', get_source_ref(url) + get_time_ref() + '.json'), 'wb') as f:
				f.write(json_bundle)
			bundle = {'entities': []}
	if len(bundle['entities']) > 0:
		with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'out',
		                       get_source_ref(url) + get_time_ref() + '.json'), 'wb') as f:
			f.write(json_bundle)

def main():

	total_time = 0
	for feed in feeds:
		start = time.time()
		convert_feed(*feed)
		end = time.time()
		time_taken = end-start
		print "Feed: %s; Time elapsed: %s" % (feed[0], str(time_taken))
		total_time += time_taken
	print 'Time taken for all feeds: ' + str(total_time)

	return

if __name__ == "__main__":
	main()