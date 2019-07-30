import git4intel
import stix2
from datetime import datetime
import random
import uuid
import json
from slugify import slugify
from pprint import pprint
import time
import unittest
import re

index_names = {
    'artifact': ['intel', 'sco'],
    'attack-pattern': ['intel', 'sdo'],
    'autonomous-system': ['intel', 'sco'],
    'campaign': ['intel', 'sdo'],
    'course-of-action': ['intel', 'sdo'],
    'directory': ['intel', 'sco'],
    'domain-name': ['intel', 'sco'],
    'email-addr': ['intel', 'sco'],
    'email-message': ['intel', 'sco'],
    'file': ['intel', 'sco'],
    'grouping': ['intel', 'sdo'],
    'identity': ['intel', 'sdo'],
    'indicator': ['intel', 'sdo'],
    'intrusion-set': ['intel', 'sdo'],
    'ipv4-addr': ['intel', 'sco'],
    'ipv6-addr': ['intel', 'sco'],
    'location': ['intel', 'sdo'],
    'mac-addr': ['intel', 'sco'],
    'malware': ['intel', 'sdo'],
    'marking-definition': ['intel'],
    'mutex': ['intel', 'sco'],
    'network-traffic': ['intel', 'sco'],
    'note': ['intel', 'sdo'],
    'observed-data': ['intel', 'sdo'],
    'opinion': ['intel', 'sdo'],
    'process': ['intel', 'sco'],
    'relationship': ['intel', 'sro'],
    'report': ['intel', 'sdo'],
    'sighting': ['intel', 'sro'],
    'software': ['intel', 'sco'],
    'threat-actor': ['intel', 'sdo'],
    'tool': ['intel', 'sdo'],
    'url': ['intel', 'sco'],
    'user-account': ['intel', 'sco'],
    'vulnerability': ['intel', 'sdo'],
    'windows-registry-key': ['intel', 'sco'],
    'x509-certificate': ['intel', 'sco'],
}


def get_deterministic_uuid(prefix=None, seed=None):
    if seed is None:
        stix_id = uuid.uuid4()
    else:
        random.seed(seed)
        a = "%32x" % random.getrandbits(128)
        rd = a[:12] + '4' + a[13:16] + 'a' + a[17:]
        stix_id = uuid.UUID(rd)

    return "{}{}".format(prefix, stix_id)


def make_valid_commit(user_id):
    ipv4 = stix2.v21.IPv4Address(value='62.171.220.83')
    domain_name = stix2.v21.DomainName(value='www.altavista.com')
    sco_data = stix2.v21.ObservedData(first_observed=datetime.now(),
                                      last_observed=datetime.now(),
                                      number_observed=1,
                                      object_refs=[ipv4.id, domain_name.id],
                                      created_by_ref=user_id)

    objs = [sco_data, domain_name, ipv4]
    grouping = stix2.v21.Grouping(context='event',
                                  object_refs=objs,
                                  created_by_ref=user_id)
    objs.append(grouping)
    bundle = json.loads(stix2.v21.Bundle(objs).serialize())
    return bundle


def make_valid_commit2(user_id):
    ipv4 = stix2.v21.IPv4Address(value='8.8.8.8')
    domain_name = stix2.v21.EmailAddress(value='admin@local.host')
    sco_data = stix2.v21.ObservedData(first_observed=datetime.now(),
                                      last_observed=datetime.now(),
                                      number_observed=1,
                                      object_refs=[ipv4.id, domain_name.id],
                                      created_by_ref=user_id)

    objs = [sco_data, domain_name, ipv4]
    grouping = stix2.v21.Grouping(context='event',
                                  object_refs=objs,
                                  created_by_ref=user_id)
    objs.append(grouping)
    bundle = json.loads(stix2.v21.Bundle(objs).serialize())
    return bundle


def make_report(user_id):
    report = stix2.v21.Report(
              name="Single IP address",
              created_by_ref=user_id,
              description="62.171.220.83",
              published=datetime.now(),
              report_types='threat-report',
              object_refs=['location--53c87d5c-a55c-4f4c-a98e-e216e91ef895'])
    return json.loads(report.serialize())


def new_user(username):
    # Feel free to add any details you like to the user/org,
    #   these are just the basics...
    new_username = username
    user_loc_id = "location--53c87d5c-a55c-4f4c-a98e-e216e91ef895"
    user_id = stix2.v21.Identity(
                         identity_class='individual',
                         name=new_username,
                         sectors=[slugify("IT Consulting & Other Services")])
    loc_rel = stix2.v21.Relationship(
                        created_by_ref=user_id.id,
                        source_ref=user_id.id,
                        target_ref=user_loc_id,
                        relationship_type='operates_at')
    bundle = json.loads(stix2.v21.Bundle([user_id, loc_rel]).serialize())
    return json.loads(user_id.serialize()), bundle


def new_org(created_by_ref):
    # Feel free to add any details you like to the user/org,
    #   these are just the basics...
    new_org_name = 'Acme Inc'
    org_loc_id = "location--53c87d5c-a55c-4f4c-a98e-e216e91ef895"
    org_id = stix2.v21.Identity(
                        created_by_ref=created_by_ref,
                        identity_class='organization',
                        name=new_org_name,
                        sectors=[slugify("IT Consulting & Other Services")])
    loc_rel = stix2.v21.Relationship(
                        source_ref=org_id.id,
                        target_ref=org_loc_id,
                        relationship_type='incorporated_at')
    bundle = json.loads(stix2.v21.Bundle([org_id, loc_rel]).serialize())
    return org_id, bundle


class TestGit4intel(unittest.TestCase):

    def test_1_setup(self):
        # Initialize
        g4i = git4intel.Client('localhost:9200')
        # Optional cleanup...
        # g4i.indices.delete_alias(index='_all', name='_all')
        # g4i.indices.delete(index='_all')

        print('Setting up indices and loading core data sets...')
        self.assertTrue(g4i.store_core_data())

        index_info = g4i.cat.indices(format='json')

        found_indices = []
        for ind in index_info:
            ind_name = ind['index'].split('--')
            if len(ind_name) > 1:
                self.assertTrue(ind_name[0] in index_names)
                self.assertTrue(re.search("[0-9]{6}", ind_name[1]))
                found_indices.append(ind_name[0])

        tmp_names = list(index_names.keys())
        self.assertTrue(found_indices.sort() == tmp_names.sort())

        aliases = g4i.cat.aliases(format='json')
        alias_test = True
        for alias in aliases:
            if len(alias['index'].split('--')) > 1:
                test_run = False
                root_name = alias['index'].split('--')[0]
                if root_name == alias['alias']:
                    test_run = True
                if alias['alias'] in index_names[root_name]:
                    test_run = True

                if not test_run:
                    alias_test = False

        self.assertTrue(alias_test)

    def test_2_setget_orgdata(self):
        g4i = git4intel.Client('localhost:9200')
        g4i.store_core_data()

        print('Creating dummy user account...')
        user_id1, user_bundle1 = new_user('NEW UZ3R')
        self.assertTrue(g4i.store_objects(user_bundle1['objects'],
                                          'register_user'))

        print('Creating dummy organisation account...')
        org_id, org_bundle = new_org(user_id1['id'])
        self.assertTrue(g4i.store_objects(org_bundle['objects'],
                                          'register_org'))

        print('Assigning created user to the created organisation...')
        org_rel1 = stix2.v21.Relationship(created_by_ref=user_id1['id'],
                                          source_ref=user_id1['id'],
                                          target_ref=org_id['id'],
                                          relationship_type='member_of')
        org_rel1 = json.loads(org_rel1.serialize())
        self.assertTrue(g4i.store_objects(org_rel1, 'org_member'))

        print('Create a second user account...')
        user_id2, user_bundle2 = new_user('Another NEW UZ3R')
        self.assertTrue(g4i.store_objects(user_bundle2['objects'],
                                          'register_user'))

        print('Invite second user to same organisation...')
        org_rel2 = stix2.v21.Relationship(created_by_ref=user_id2['id'],
                                          source_ref=user_id2['id'],
                                          target_ref=org_id['id'],
                                          relationship_type='member_of')
        org_rel2 = json.loads(org_rel2.serialize())
        self.assertTrue(g4i.store_objects(org_rel2, 'org_member'))

        print('Set a new area of operations for the org...')
        ao_rel = stix2.v21.Relationship(
                created_by_ref=user_id2['id'],
                source_ref=org_id['id'],
                target_ref='location--70924011-7eb0-452d-aaca-15b0979791c6',
                relationship_type='operates_at')
        ao_rel = json.loads(ao_rel.serialize())
        self.assertTrue(g4i.store_objects(ao_rel, 'area_of_operation'))

        start = time.time()
        org_info = g4i.get_my_org_info(user_id=user_id2['id'])
        end = time.time()
        print('Get my org data took: ' + str(end-start))

        org_ids = []
        ind_ids = []
        rels = {}
        for obj in org_info:
            if obj['type'] == 'identity':
                if obj['identity_class'] == 'organization':
                    org_ids.append(obj['id'])
                else:
                    ind_ids.append(obj['id'])
            elif obj['type'] == 'relationship':
                rels[obj['source_ref']] = obj['target_ref']

        self.assertTrue(len(org_ids) > 0)
        self.assertTrue(len(ind_ids) > 0)

        rel_test = True
        for rel in rels:
            test_run = False
            if rel in org_ids:
                if rels[rel] in ind_ids:
                    test_run = True
            if rel in ind_ids:
                if rels[rel] in org_ids:
                    test_run = True
            if not test_run:
                rel_test = False

        self.assertTrue(rel_test)

    def test_3_setget_intel(self):
        g4i = git4intel.Client('localhost:9200')
        g4i.store_core_data()

        # Make a valid commit from Adam's suggested 'event' data as a grouping
        print('Making 2 event commits...')
        user_id1, user_bundle1 = new_user('NEW UZ3R')
        bundle = make_valid_commit(user_id1['id'])
        self.assertTrue(g4i.store_objects(objects=bundle['objects'],
                                          molecule_types='event'))
        user_id2, user_bundle2 = new_user('Another NEW UZ3R')
        bundle = make_valid_commit2(user_id2['id'])
        self.assertTrue(g4i.store_objects(objects=bundle['objects'],
                                          molecule_types='event'))

        print('Making random report...')
        report = make_report(user_id1['id'])
        self.assertTrue(g4i.store_objects(objects=report))

    def test_5_get_objects(self):
        # Test for search where objid is known
        # Include searches for values within
        g4i = git4intel.Client('localhost:9200')
        g4i.store_core_data()

        user_id1, user_bundle1 = new_user('NEW UZ3R')
        report = make_report(user_id1['id'])
        g4i.store_objects(objects=report)

        # Give enough time to index...
        time.sleep(2)

        obj_id = report['id']
        # Search just objid (test correct id)
        res = g4i.get_objects(user_id=user_id1['id'], obj_ids=[obj_id])
        self.assertTrue(res[0]['id'] == obj_id)

        value = '62.171.220.83'
        # Search objid with values (test value contained - str search)
        res = g4i.get_objects(user_id=user_id1['id'],
                              obj_ids=[obj_id],
                              values=[value])
        self.assertTrue(value in str(res))

    def test_6_get_content(self):
        # Test for search where objid is not known
        # Include:
        # - searches for values within
        # - searches for certain types
        # - searches for grouping special case
        # - Combinations of above

        g4i = git4intel.Client('localhost:9200')
        g4i.store_core_data()

        user_id1, user_bundle1 = new_user('NEW UZ3R')
        bundle = make_valid_commit(user_id1['id'])
        g4i.store_objects(objects=bundle['objects'], molecule_types='event')
        org_id, org_bundle = new_org(user_id1['id'])
        g4i.store_objects(org_bundle['objects'], 'register_org')
        user_id2, user_bundle2 = new_user('Another NEW UZ3R')
        bundle = make_valid_commit2(user_id2['id'])
        g4i.store_objects(objects=bundle['objects'], molecule_types='event')

        report = make_report(user_id1['id'])
        self.assertTrue(g4i.store_objects(objects=report))

        time.sleep(2)

        # Values only - observable value (report and sco)
        value = '62.171.220.83'
        res = g4i.get_content(user_id=user_id1['id'],
                              values=[value])

        for obj in res:
            if obj['id'] == report['id']:
                self.assertTrue(value in str(obj))
            elif obj['type'] == 'grouping' or obj['type'] == 'observed-data':
                test_value = obj['x_eiq_object_refs_objects'][0]['value']
                self.assertTrue(test_value == value)
            else:
                self.assertTrue(False)
        self.assertTrue(len(res) == 3)

        # Types only
        _type = 'observed-data'
        res = g4i.get_content(user_id=user_id1['id'],
                              types=[_type])
        for obj in res:
            if obj['type'] == 'observed-data':
                test_value = obj['x_eiq_object_refs_objects']
                self.assertTrue(len(test_value) == 2)
            else:
                self.assertTrue(False)
        self.assertTrue(len(res) == 1)

        # Grouping with context set - event
        group_type = 'event'
        res = g4i.get_content(user_id=user_id1['id'],
                              types=['grouping'],
                              group_contexts=[group_type])
        for obj in res:
            if obj['type'] == 'grouping':
                self.assertTrue(obj['context'] == 'event')

        # Values and types - report/sco filter
        res = g4i.get_content(user_id=user_id1['id'],
                              types=[_type],
                              values=[value])
        for obj in res:
            if obj['type'] == 'observed-data':
                test_value = obj['x_eiq_object_refs_objects'][0]['value']
                self.assertTrue(test_value == value)
            else:
                self.assertTrue(False)

        # Values and grouping with context - ip address from event
        res = g4i.get_content(user_id=user_id1['id'],
                              types=['grouping'],
                              group_contexts=[group_type],
                              values=[value])
        for obj in res:
            if obj['type'] == 'grouping':
                self.assertTrue(obj['context'] == 'event')
                test_value = obj['x_eiq_object_refs_objects'][0]['value']
                self.assertTrue(test_value == value)
            else:
                self.assertTrue(False)

        # Additional types and grouping with context - grouping and identity
        res = g4i.get_content(user_id=user_id1['id'],
                              types=['grouping', 'identity'],
                              group_contexts=[group_type])
        for obj in res:
            if obj['type'] == 'grouping':
                self.assertTrue(obj['context'] == 'event')
                self.assertTrue(len(obj['x_eiq_object_refs_objects']) == 3)
                for obs in obj['x_eiq_object_refs_objects']:
                    self.assertTrue(type(obs) is dict)
            elif obj['type'] == 'identity':
                self.assertTrue(True)
            else:
                self.assertTrue(False)
        self.assertTrue(len(res) == 2)

        # Values, types and grouping with context - grouping, identity and sco
        #   value
        res = g4i.get_content(user_id=user_id1['id'],
                              types=['grouping', 'report'],
                              group_contexts=[group_type],
                              values=[value])
        for obj in res:
            if obj['type'] == 'grouping':
                self.assertTrue(obj['context'] == 'event')
                test_value = obj['x_eiq_object_refs_objects'][0]['value']
                self.assertTrue(test_value == value)
            elif obj['type'] == 'report':
                self.assertTrue(value in str(obj))
            else:
                self.assertTrue(False)
        self.assertTrue(len(res) == 2)

        # Eventually add my_org_only == False when md filtering applied


if __name__ == '__main__':
    unittest.main()
