from eiqjson import get_uuid, make_indicator, make_ttp, make_relationship, make_report
from functions import string_query
import sys
from pprint import pprint
import dateutil.parser

global ref_objects

def set_ref_objects():
	global ref_objects
	ref_objects = {}

def check_entity_name(entity_name, entity_type):
	entity_id = None
	# Test 1: Check if in ref-objects (created this session)
	# Test 2: Check if in platform by string search for title
	# Return None if not found (or not sure - too many hits), otherwise return entity_id
	try:
		entity_id = ref_objects[entity_name]
	except KeyError:
		pass

	if entity_id is None:
		q_string = "data.type:%s AND data.title:\"%s\"" % (entity_type, entity_name)
		out = string_query(q_string)
		try:
			hits = out['hits']['hits']
			if len(hits) == 1:
				entity_id = str(hits[0]['_id'])
			elif len(hits) > 1:
				print "Too many hits for \"%s\"" % q_string
		except KeyError:
			pass

	return entity_id

def add_library_entity(entities, new_entity_args, new_entity_type):
	entity_id = check_entity_name(new_entity_args['name'], new_entity_type)

	if entity_id is None:
		# Does not already exist - create the new entity and add to entities
		module_name = 'make_%s' % new_entity_type
		new_entity = getattr(sys.modules[__name__], module_name)(**new_entity_args)
		entities.append(new_entity)
		entity_id = new_entity['id']
		ref_objects[new_entity_args['name']] = entity_id
	return entities, entity_id

def singleip(item):
	ind_args = {
		'name': str(item),
		'type': 'IP Watchlist',
	}
	entities = singleind(ind_args)
	return entities

def singledomain(item):
	ind_args = {
		'name': str(item),
		'type': 'Domain Watchlist',
	}
	entities = singleind(ind_args)
	return entities

def singlehash(item):
	ind_args = {
		'name': str(item),
		'type': 'File Hash Watchlist',
	}
	entities = singleind(ind_args)
	return entities

def singleurl(item):
	ind_args = {
		'name': str(item),
		'type': 'URL Watchlist',
	}
	entities = singleind(ind_args)
	return entities

def singleind(ind_args):
	entities = []
	entities, ind_id = add_library_entity(entities, ind_args, 'indicator')
	return entities

def bambenek(item):
	entities = []
	if not item.startswith("#"):
		entries = item.split(',')
		malware_name = entries[5].rsplit('/', 1)[1].rsplit('.', 1)[0]
		malware_args = {
			'name': malware_name + ' Malware',
			'confidence': 'Medium',
			'intended_effects': ['Advantage'],
			'description': '<p>' + entries[4] + '</p>',
			'references': [entries[5]],
			'malware_name': malware_name  + ' Malware',
		}
		c2_args = {
			'name': malware_name + ' C2',
			'confidence': 'Medium',
			'intended_effects': ['Advantage'],
			'description': '<p>' + entries[4] + '</p>',
			'references': [entries[5]],
		}

		ip_args = {
			'name': entries[1],
			'type': 'IP Watchlist',
		}
		domain_args = {
			'name': entries[0],
			'type': 'Domain Watchlist',
		}

		entities, ip_id = add_library_entity(entities, ip_args, 'indicator')
		entities, domain_id = add_library_entity(entities, domain_args, 'indicator')

		entities, ttp_malware_id = add_library_entity(entities, malware_args, 'ttp')
		entities, ttp_c2_id = add_library_entity(entities, c2_args, 'ttp')

		entities.append(make_relationship(domain_id, ip_id, 'indicator', 'indicator', 'related_indicators'))
		entities.append(make_relationship(ttp_malware_id, ttp_c2_id, 'ttp', 'ttp', 'related_ttps'))
		entities.append(make_relationship(domain_id, ttp_c2_id, 'indicator', 'ttp', 'indicated_ttps'))
	return entities

def bambenek_dga(item):
	entities = []
	if not item.startswith("#"):
		detail = item.split(',')
		tmp_date = dateutil.parser.parse(detail[2])
		ttp_args = {
			'name': detail[1],
			'confidence': 'Medium',
			'intended_effects': ['Advantage'],
			'description': '<p>' + detail[1] + '</p>',
			'references': [detail[3]],
		}

		entities, ttp_id = add_library_entity(entities, ttp_args, 'ttp')
		ind = make_indicator(name=detail[0], type='Domain Watchlist', last_reported=tmp_date.isoformat('T') + '+00:00')
		entities.append(ind)
		entities.append(make_relationship(ind['id'], ttp_id, 'indicator', 'ttp', 'indicated_ttps'))


	return entities

def dangerrulez(item):
	entities = []
	if not item.startswith("#"):
		detail = item.split('\t')
		value = detail[0]
		last_reported = detail[2][2:]
		value_id = detail[5]
		ind = make_indicator(name=value,
		                     description='<p>Suspected SSH brute forcing activity. Unique Danger Rulez reference number: ' + value_id + '</p>',
		                     type='IP Watchlist', last_reported=last_reported)
		entities.append(ind)
	return entities

def malc0de(item):
	entities = []
	domain_value = item.title.text.encode('utf8').strip()
	description = item.description.text.encode('utf8')
	detail = {}
	for entry in description.split(','):
		entry_pair = entry.split(':')
		pair_name = entry_pair[0].strip()
		pair_value = entry_pair[1].strip()
		if pair_value == '' and pair_name == 'URL':
			detail[pair_name] = domain_value
		else:
			detail[pair_name] = pair_value

	ip_args = {
		'name': detail['IP Address'],
		'type': 'IP Watchlist',
	}
	url_args = {
		'name': detail['URL'],
		'type': 'URL Watchlist',
	}
	hash_args = {
		'name': detail['MD5'],
		'type': 'File Hash Watchlist',
	}

	entities, ip_id = add_library_entity(entities, ip_args, 'indicator')
	entities, url_id = add_library_entity(entities, url_args, 'indicator')
	entities, hash_id = add_library_entity(entities, hash_args, 'indicator')

	hash_rel = make_relationship(url_id, hash_id, 'indicator', 'indicator', 'related_indicators')
	ip_rel = make_relationship(url_id, ip_id, 'indicator', 'indicator', 'related_indicators')

	entities.append(hash_rel)
	entities.append(ip_rel)
	return entities

def blocklist_de(item, output_type):
	entities = []
	blocklist_type = output_type.split('blocklist_de')[1]
	if blocklist_type == '_bots':
		name = '[blocklist_de] Malicious Bots'
		intended_effects = ['Denial and Deception']
		description = "IP addresses which have been reported within the last 48 hours as having run attacks attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki)."
	elif blocklist_type == '_apache':
		name = '[blocklist_de] DDoS of Apache Servers'
		intended_effects = ['Degradation of Service']
		description = "Source IP addresses related to DDoS of Apache servers."
	elif blocklist_type == '_brute':
		name = '[blocklist_de] Brute Force Website Logins'
		intended_effects = ['Account Takeover']
		description = "IPs which attack Joomlas, Wordpress and other Web-Logins with Brute-Force Logins."
	elif blocklist_type == '_ftp':
		name = '[blocklist_de] FTP Attacks'
		intended_effects = ['Unauthorized Access']
		description = "IP addresses which have been reported within the last 48 hours for attacks on the Service FTP."
	elif blocklist_type == '_imap':
		name = '[blocklist_de] IMAP Attacks'
		intended_effects = ['Unauthorized Access']
		description = "IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3."
	elif blocklist_type == '_mail':
		name = '[blocklist_de] Mail Protocol Attacks'
		intended_effects = ['Unauthorized Access']
		description = "IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix."
	elif blocklist_type == '_sip':
		name = '[blocklist_de] Voice Protocol Attacks'
		intended_effects = ['Unauthorized Access']
		description = "IP addresses that tried to login in a SIP-, VOIP- or Asterisk-Server."
	elif blocklist_type == '_ssh':
		name = '[blocklist_de] SSH Attacks'
		intended_effects = ['Unauthorized Access']
		description = "IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH."
	elif blocklist_type == '_strongips':
		name = '[blocklist_de] High Confidence Malicious Infrastructure'
		intended_effects = ['Unauthorized Access']
		description = "High confidence malicious IPs, ie: which are older then 2 month and have more than 5000 attacks."
	else:
		raise ValueError('[-][pre-processor] Error: ' + blocklist_type + ' is not a valid blocklist_de type.')

	blocklist_args = {
		'name': name,
		'confidence': 'Medium',
		'intended_effects': intended_effects,
		'description': '<p>' + description + '</p>',
	}

	ip_args = {
		'name': item,
		'type': 'IP Watchlist',
	}

	entities, ttp_blocklist_id = add_library_entity(entities, blocklist_args, 'ttp')
	entities, ip_id = add_library_entity(entities, ip_args, 'indicator')

	rel = make_relationship(ip_id, ttp_blocklist_id, 'indicator', 'ttp', 'indicated_ttps')
	entities.append(rel)

	return entities

def news(item):
	entities = []
	title = item.title.text.encode('utf8').strip()
	description = item.description.text
	references = [item.link.text]
	try:
		tmp_datetime = dateutil.parser.parse(item.pubDate.text)
		pub_date = tmp_datetime.isoformat('T') + '+00:00'
	except AttributeError:
		pub_date = None
	report = make_report(name=title, description=description, intents=['Collective Threat Intelligence'],
	                     pub_date=pub_date, references=references)

	entities.append(report)
	return entities

def fidelis(item, output_type):
	entities = []
	if not item.startswith("#"):
		detail = item.split(',')

		ttp_args = {
			'name': detail[1],
			'confidence': 'Medium',
			'intended_effects': ['Advantage'],
			'description': '<p>' + detail[1] + '</p>',
		}

		entities, ttp_ip_id = add_library_entity(entities, ttp_args, 'ttp')

		feed_type = output_type.split('fidelis_')[1]
		if feed_type == "masterip":
			ind_args = {
				'name': detail[0],
				'type': 'IP Watchlist',
			}
		elif feed_type == "masterdomain":
			ind_args = {
				'name': detail[0],
				'type': 'Domain Watchlist',
			}
		else:
			raise ValueError('[-][pre-processor] Error: ' + feed_type + ' is not a valid fidelis type.')
		ind, ind_id = add_library_entity(entities, ind_args, 'indicator')
		ttp_rel = make_relationship(ind_id, ttp_ip_id, 'indicator', 'ttp', 'indicated_ttps')
		entities.append(ttp_rel)
	return entities