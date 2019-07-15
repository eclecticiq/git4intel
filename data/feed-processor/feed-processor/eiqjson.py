import uuid
import datetime
# from config import *

def get_uuid(in_string = None):
	if in_string is None:
		return uuid.uuid4()
	else:
		return str(uuid.uuid5(uuid.NAMESPACE_DNS, in_string))

def make_report(name, description, intents, pub_date=None, references=None, tags=None):
	if pub_date is None:
		report_time = datetime.datetime.utcnow().isoformat('T') + '+00:00'
	else:
		report_time = pub_date
	report_id = get_uuid(name)

	new_report = {
      "data": {
	      "description": description,
	      "description_structuring_format": "html",
        "title": name,
        "type": "report"
      },
      "id": report_id,
      "meta": {
        "estimated_observed_time": report_time,
        "estimated_threat_start_time": report_time,
      },
	}

	if type(references) is list:
		new_report['data']['information_source'] = {
			'type': 'information-source',
			'references': references,
		}
	else:
		raise ValueError("[-][pre-processor] 'Report' entity attribute 'references' must be type 'list'")

	if type(intents) is list:
		new_report['data']['intents'] = []
		for intent in intents:
			new_intent = {
				'value': intent,
			}
			new_report['data']['intents'].append(new_intent)
	else:
		raise ValueError("[-][pre-processor] 'Report' entity must have 'intents' (list)")

	if type(tags) is list:
		new_report['meta']['tags'] = tags

	return new_report

def make_indicator(name, type, description=None, last_reported=None):
	# Assumes 'name' is the Indicator value for extraction to be performed on it
	if last_reported is None:
		time_now = datetime.datetime.utcnow().isoformat('T') + '+00:00'
	else:
		time_now = last_reported
	ind_id = get_uuid(name)

	new_indicator = {
      "data": {
        "type": "indicator",
        "title": name,
        "types": [
          {
            "value": type
          },
        ],
      },
      "id": ind_id,
      "meta": {
        "estimated_threat_start_time": time_now,
        "estimated_observed_time": time_now,
      },
      "relevancy": 1.0,
    }

	if description is not None:
		new_indicator['data']['description'] = description
		new_indicator['data']['description_structuring_format'] = 'html'

	return new_indicator

def make_ttp(name, confidence, intended_effects, description=None, capec_id=None, references=None, malware_name=None):
	time_now = datetime.datetime.utcnow().isoformat('T') + '+00:00'
	ttp_id = get_uuid(name)

	new_ttp = {
		'data': {
			'type': 'ttp',
			'title': name,

			'confidence': {
				'value': confidence,
				'type': 'confidence',
			},
		},
		'id': ttp_id,
		'meta': {
			'estimated_observed_time': time_now,
			'estimated_threat_start_time': time_now,
		},
	}

	if type(intended_effects) is list:
		new_ttp['data']['intended_effects'] = []
		for effect in intended_effects:
			new_effect = {
				'value': effect,
				'type': 'statement',
			}
			new_ttp['data']['intended_effects'].append(new_effect)
	else:
		raise ValueError("[-][pre-processor] 'TTP' entity must have 'intended_effects' (list)")

	if capec_id is not None:
		new_ttp['data']['behavior'] = {
			'type': 'behavior',
			'attack_patterns': [
				{
					'title': name,
					'capec_id': capec_id,
					'type': 'attack-pattern',
				},
			],
		}

	if malware_name is not None:
		new_ttp['data']['behavior'] = {
			'type': 'behavior',
			'malware': [
				{
					'type': 'malware-instance',
					'names': [
						{
							'value': malware_name,
						},
					],
				},
			],
		}

	if references is not None:
		new_ttp['data']['information_source'] = {
			'type': 'information-source',
			'references': references,
		}

	if description is not None:
		new_ttp['data']['description'] = description
		new_ttp['data']['description_structuring_format'] = 'html'

	return new_ttp

def make_actor(name, actor_type, confidence, references=None, description=None):
	time_now = datetime.datetime.utcnow().isoformat('T') + '+00:00'
	actor_id = get_uuid(name)

	new_actor = {
		'data': {
			'types': [
				{
					'value': actor_type,
					'type': 'statement',
				},
			],
			'type': 'threat-actor',
			'title': name,
			'confidence': {
				'value': confidence,
				'type': 'confidence',
			},
			'identity': {
				'name': name,
				'type': 'identity',
			},
		},
		'id': actor_id,
		'meta': {
			'estimated_observed_time': time_now,
			'estimated_threat_start_time': time_now,
		},
	}

	if references is not None:
		new_actor['data']['information_source'] = {
			'type': 'information-source',
			'references': references,
		}
	if description is not None:
		new_actor['data']['description'] = description
		new_actor['data']['description_structuring_format'] = 'html'

	return new_actor

def make_campaign(name, confidence, intended_effects, status=None):
	time_now = datetime.datetime.utcnow().isoformat('T') + '+00:00'
	cam_id = get_uuid(name)

	new_campaign = {
		'data': {
			'type': 'campaign',
			'title': name,
			'confidence': {
				'value': confidence,
				'type': 'confidence',
			},
		},
		'id': cam_id,
		'meta': {
			'estimated_observed_time': time_now,
			'estimated_threat_start_time': time_now,
		},
	}

	if status is not None:
		new_campaign['data']['status'] = status
	else:
		new_campaign['data']['status'] = 'Historic'

	if type(intended_effects) is list:
		new_ttp['data']['intended_effects'] = []
		for effect in intended_effects:
			new_effect = {
				'value': effect,
				'type': 'statement',
			}
			new_campaign['data']['intended_effects'].append(new_effect)
	else:
		raise ValueError("[-][pre-processor] 'Campaign' entity must have 'intended_effects' (list)")

	return new_campaign

def make_relationship(source_id, target_id, source_type, target_type, key):
	rel_id = get_uuid(source_id + target_id)

	new_relationship = {
		'data': {
			'source': source_id,
			'type': 'relation',
			'target': target_id,
			'target_type': target_type,
			'source_type': source_type,
			'key': key,
		},
		'id': rel_id,
		'relevancy': 1.0,
		'meta': {
		}
	}
	return new_relationship