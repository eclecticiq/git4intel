import requests
import json
import uuid
from config import settings
import sys

# def get_uuid(in_string):
# 	return str(uuid.uuid5(uuid.NAMESPACE_DNS, in_string))

def platform_auth():
	USERNAME = settings('general')['platform_username']
	PASSWORD = settings('general')['platform_password']
	ENDPOINT = settings('general')['platform_url'] + '/auth'
	data = {'username': USERNAME, 'password': PASSWORD}
	headers = {'Content-Type': 'application/json'}
	r = requests.post(ENDPOINT, data=json.dumps(data), headers=headers, verify=False)
	response = r.json()
	return response['token']

# def check_entity_id(entity_id):
# 	found = False
# 	ENDPOINT = settings('general')['platform_url'] + '/' + entity_id
# 	token = platform_auth()
# 	headers = {
# 		'Content-Type': 'application/json',
# 		'Accept': 'application/json',
# 		'Authorization': 'Bearer ' + token,
# 	}
# 	r = requests.get(ENDPOINT, headers=headers, verify=False)
#
# 	try:
# 		err_response = r.json()['errors'][0]['title']
# 	except KeyError:
# 		found = True
#
# 	if found is False:
# 		if entity_id in ref_objects:
# 			found = True
# 		else:
# 			ref_objects.append(entity_id)
# 	return found

def string_query(qstring):
	ENDPOINT = settings('general')['platform_url'] + '/search/stix/_search'
	query = {
		'query': {
			'query_string': {
				'query': qstring
			}
		}
	}
	token = platform_auth()
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json',
		'Authorization': 'Bearer ' + token,
	}
	r = requests.post(ENDPOINT, json=query, headers=headers, verify=False)
	return r.json()