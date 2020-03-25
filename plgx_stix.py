# Only needed for the CTI get, replace with your own
import git4intel
from git4intel.utils import hits_from_res

# For the new plgx endpoints, install the cobsec fork
from polylogyx_apis.api import PolylogyxApi

import json
import random
import uuid
import re

g4i = git4intel.Client('localhost:9200')

# Vanilla plgx server setup...
domain = '127.0.0.1'
username = 'admin'
password = 'admin'
plgx = PolylogyxApi(domain=domain, username=username, password=password)


def get_deterministic_uuid(prefix=None, seed=None):
    if seed is None:
        stix_id = uuid.uuid4()
    else:
        random.seed(seed)
        a = "%32x" % random.getrandbits(128)
        rd = a[:12] + '4' + a[13:16] + 'a' + a[17:]
        stix_id = uuid.UUID(rd)

    return "{}{}".format(prefix, stix_id)


def main():

    # User selects a "threat" concept that they want to detect by id...
    pteranodon = 'malware--5f9f7648-04ba-4a9f-bb4c-2a13e74572bd'
    packs = {}

    # Run the query in CTI data to get the info we need...
    #  Replace this with your relevant "get CTI" query.
    res = g4i.get_molecule(
        user_id=g4i.identity['id'],
        stix_ids=[pteranodon],
        schema_name="mitre",
        objs=True,
        pivot=False)

    # Just because of the way that get_molecule() works, I'm doing some client
    #  side parsing here to get the data I need for plgx. Of course, this part
    #  will be different depending on your CTI query and I know it's a hack!
    techniques = []
    pattern = re.compile(r'TA\d{4}|[T|S|G|M]\d{4}')
    for obj in hits_from_res(res):
        if 'external_references' not in obj:
            continue
        if 'kill_chain_phases' not in obj:
            continue
        for ref in obj['external_references']:
            if 'external_id' not in ref:
                continue
            if pattern.search(ref['external_id']):
                mitre_id = ref['external_id']
                break
        techniques.append((mitre_id, obj['id']))

    ind_refs = []
    done_rels = []
    for obj in hits_from_res(res):
        if obj['id'] in done_rels:
            continue
        if obj['type'] != 'relationship':
            continue
        done_rels.append(obj['id'])
        if obj['relationship_type'] != 'indicates':
            continue
        for technique in techniques:
            if obj['target_ref'] != technique[1]:
                continue
            new_tup = (technique[0], technique[1], obj['source_ref'])
            if new_tup not in ind_refs:
                ind_refs.append((technique[0], technique[1], obj['source_ref']))
            break
    # ...and that's the end of that nonsense!!! Now you have the info you need.

    # This bit restructures the data in to a simple dict of style:
    #  {'<mitre_technique_id>': {<associated_osquery_pack>}}
    # Created the format to enable fownstream data granularity with plgx api.
    packs = {}
    for hit in hits_from_res(res):
        for ind_ref in ind_refs:
            if hit['id'] != ind_ref[2]:
                continue
            packs[ind_ref[0]] = json.loads(hit['pattern'])

    # And now that the data is all in the right format -
    #  send to the plgx endpoint.
    tags = ['all']
    alerters = ['email', 'debug']
    res = plgx.deploy_threat_packs(
        packs=packs,
        threat_name=pteranodon,
        tags=tags,
        alerters=alerters)

    print(res)

    # try:
    #     rule_data = plgx.get_rules()['results']['data']
    # except KeyError:
    #     print('Failed to get rule data!')
    #     return False

    # for rule in rule_data:
    #     print(plgx.get_stix_sightings(rule_id=rule['id']))

    # tag_data = plgx.get_tags()
    # print(tag_data)

    # for tag in tag_data['results']['data']:
    #     print(tag)
    #     for node in tag['nodes']:
    #         print(node.lower())


if __name__ == '__main__':
    main()
