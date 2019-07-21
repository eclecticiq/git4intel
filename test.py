from git4intel import Client
from pprint import pprint
import stix2
from datetime import datetime
import unittest

client = Client('localhost:9200')
client.setup_es("21")


def make_valid_commit():
    ident = stix2.v21.Identity(identity_class='individual', name='cobsec')
    ipv4 = stix2.v21.IPv4Address(value='8.8.8.8')
    domain_name = stix2.v21.DomainName(
        value='google.com')
    obs_data = stix2.v21.ObservedData(first_observed=datetime.now(
    ), last_observed=datetime.now(), number_observed=1, object_refs=[ipv4.id, domain_name.id], created_by_ref=ident.id)
    atp_hunter = stix2.v21.AttackPattern(
        name="ATP Phase Definition from Hunter", created_by_ref=ident.id)
    ind_event = stix2.v21.Indicator(name="Collection of Observed Data signifying Event", labels=[
                                    'malicious-activity'], pattern="[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019e']", pattern_type='stix', indicator_types=['malicious-activity'], created_by_ref=ident.id)
    rel_obsdata_ind = stix2.v21.Relationship(
        source_ref=ind_event.id, target_ref=atp_hunter.id, relationship_type='indicates', created_by_ref=ident.id)
    rel_atp_mitre = stix2.v21.Relationship(
        source_ref=atp_hunter.id, target_ref='attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add', relationship_type='relates_to', created_by_ref=ident.id)
    rel_ind_obsdata = stix2.v21.Relationship(
        source_ref=ind_event.id, target_ref=obs_data.id, relationship_type='based_on', created_by_ref=ident.id)

    objs = [obs_data, domain_name, ipv4, atp_hunter, ind_event,
            rel_atp_mitre, rel_obsdata_ind, rel_ind_obsdata, ident]
    grouping = stix2.v21.Grouping(
        context='g4i commit', object_refs=objs, created_by_ref=ident.id)

    objs.append(grouping)

    bundle = stix2.v21.Bundle(objs)
    return bundle


def remove_type_from_commit(commit, _type):
    new_objs = []
    for obj in commit.objects:
        if obj.type != _type:
            new_objs.append(obj)
    return stix2.v21.Bundle(new_objs)


class TestGit4intel(unittest.TestCase):

    def test_search(self):
        q = {
            "query": {
                "match_all": {}
            },
            "stored_fields": []
        }
        res = client.search(index='intel', body=q, size=10000)
        self.assertNotEqual(0, res['hits']['total']['value'])

    def test_index_exists(self):
        self.assertTrue(client.indices.exists(index=['intel']))

    def test_commit_ident(self):
        test_commit = remove_type_from_commit(make_valid_commit(), 'identity')
        self.assertFalse(client.check_commit(test_commit))

    def test_commit_group(self):
        test_commit = remove_type_from_commit(make_valid_commit(), 'grouping')
        self.assertFalse(client.check_commit(test_commit))


if __name__ == '__main__':
    unittest.main()
