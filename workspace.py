import git4intel
from git4intel.utils import hits_from_res
from elasticsearch import helpers
import stix2
import json
from slugify import slugify
from pprint import pprint
import random
import uuid
from datetime import datetime
import time
import sys
import requests
import base64
import re
import os

from polylogyx_apis.api import PolylogyxApi

from html.parser import HTMLParser
from html.entities import name2codepoint


class MyHTMLParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        print("Start tag:", tag)
        for attr in attrs:
            print("     attr:", attr)

    def handle_endtag(self, tag):
        print("End tag  :", tag)


g4i = git4intel.Client('localhost:9200')

admin_fields = [
    'spec_version',
    'id',
    'type',
    'created',
    'modified',
    'created_by_ref',
    'revoked',
    'confidence',
    'lang',
    'object_marking_refs',
    'granular_markings',
    'defanged',
    'external_references',
    'valid_from'
]


def get_deterministic_uuid(prefix=None, seed=None):
    if seed is None:
        stix_id = uuid.uuid4()
    else:
        random.seed(seed)
        a = "%32x" % random.getrandbits(128)
        rd = a[:12] + '4' + a[13:16] + 'a' + a[17:]
        stix_id = uuid.UUID(rd)

    return "{}{}".format(prefix, stix_id)


def make_sighting(ind_id):

    tlp = stix2.v21.common.TLP_GREEN.id
    pii = g4i.pii_marking['id']
    atime = '2020-02-24T13:18:21.477143Z'
    ctime = '2020-02-24T13:18:19.477143Z'
    mtime = '2020-02-24T13:18:20.477143Z'

    sensor_name = 'OSQuery Agent 56b650'
    sensor_id = get_deterministic_uuid(prefix='identity--',
                                       seed=sensor_name)

    sensor_ident = stix2.v21.Identity(id=sensor_id,
                                      name=sensor_name,
                                      identity_class='system',
                                      object_marking_refs=[pii])

    directory = stix2.v21.Directory(path="C:\\Windows\\%")
    file = stix2.v21.File(hashes={'MD5': 'ce60a5c89ea89a8f7acd0103a786f407'},
                          name='ajbfjeklr.exe',
                          parent_directory_ref=directory.id,
                          atime=atime,
                          ctime=ctime,
                          mtime=mtime)
    obsdata = stix2.v21.ObservedData(created_by_ref=sensor_id,
                                     first_observed=datetime.now(),
                                     last_observed=datetime.now(),
                                     number_observed=1,
                                     object_refs=[file.id],
                                     object_marking_refs=[tlp])

    sighting = stix2.v21.Sighting(created_by_ref=sensor_id,
                                  sighting_of_ref=ind_id,
                                  observed_data_refs=[obsdata.id],
                                  where_sighted_refs=[sensor_id],
                                  object_marking_refs=[tlp])

    objects = [directory, file, obsdata, sensor_ident, sighting]

    bundle = json.loads(stix2.v21.Bundle(objects=objects).serialize())
    return bundle


def make_org(username1, username2, orgname):
    pii_dm = g4i.pii_marking['id']
    sector = slugify("IT Consulting & Other Services")
    location = "location--ed901153-d634-4825-aea4-64f771c30433"
    user1 = stix2.v21.Identity(name=username1,
                               identity_class='individual',
                               sectors=[sector],
                               object_marking_refs=[pii_dm])

    user2 = stix2.v21.Identity(name=username2,
                               identity_class='individual',
                               sectors=[sector],
                               object_marking_refs=[pii_dm])

    org = stix2.v21.Identity(name=orgname,
                             identity_class='organization',
                             sectors=[sector],
                             object_marking_refs=[pii_dm])

    member1 = stix2.v21.Relationship(created_by_ref=user1.id,
                                     source_ref=user1.id,
                                     target_ref=org.id,
                                     relationship_type='member-of',
                                     object_marking_refs=[pii_dm])

    member2 = stix2.v21.Relationship(created_by_ref=user2.id,
                                     source_ref=user2.id,
                                     target_ref=org.id,
                                     relationship_type='member-of',
                                     object_marking_refs=[pii_dm])

    org_loc = stix2.v21.Relationship(created_by_ref=org.id,
                                     source_ref=org.id,
                                     target_ref=location,
                                     relationship_type='incorporated-at',
                                     object_marking_refs=[pii_dm])

    user1_loc = stix2.v21.Relationship(created_by_ref=user1.id,
                                       source_ref=user1.id,
                                       target_ref=location,
                                       relationship_type='operates-at',
                                       object_marking_refs=[pii_dm])

    user2_loc = stix2.v21.Relationship(created_by_ref=user2.id,
                                       source_ref=user2.id,
                                       target_ref=location,
                                       relationship_type='operates-at',
                                       object_marking_refs=[pii_dm])

    objects = [user1, user2, org, member1, member2, org_loc, user1_loc,
               user2_loc]

    bundle = json.loads(stix2.v21.Bundle(objects=objects).serialize())
    return bundle['objects'], [org.id, user1.id, user2.id]


def make_incident(user_id, target_org, tlp, tlp_dist=None):
    if tlp == 'white':
        tlp = stix2.v21.common.TLP_WHITE.id
    elif tlp == 'green':
        tlp = stix2.v21.common.TLP_GREEN.id
    elif tlp == 'amber' or tlp == 'red':
        if tlp == 'amber':
            tlp_def_ref = stix2.v21.common.TLP_AMBER.id
        else:
            tlp_def_ref = stix2.v21.common.TLP_RED.id
        tlp = g4i.set_tlpplus(user_id=user_id,
                              md_name="Super Secret Distro...",
                              tlp_marking_def_ref=tlp_def_ref,
                              distribution_refs=tlp_dist)[0]
    obs1 = stix2.v21.IPv4Address(value='62.171.220.83')
    obs2 = stix2.v21.DomainName(value='www.altavista.com')
    obsdata = stix2.v21.ObservedData(created_by_ref=user_id,
                                     first_observed=datetime.now(),
                                     last_observed=datetime.now(),
                                     number_observed=1,
                                     object_refs=[obs1.id, obs2.id],
                                     object_marking_refs=[tlp])
    pattern = (
       "[file:hashes.'SHA-256' = "
       "'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']")
    ind = stix2.v21.Indicator(created_by_ref=user_id,
                              name='EVENT',
                              pattern=pattern,
                              pattern_type='stix',
                              valid_from=datetime.now(),
                              indicator_types=['malicious-activity'],
                              object_marking_refs=[tlp])

    based = stix2.v21.Relationship(created_by_ref=user_id,
                                   source_ref=ind.id,
                                   target_ref=obsdata.id,
                                   relationship_type='based-on',
                                   object_marking_refs=[tlp])
    phase_atp = stix2.v21.AttackPattern(created_by_ref=user_id,
                                        name='PHASE',
                                        aliases=['EIQ-PHASE-derp'],
                                        object_marking_refs=[tlp])
    indicate = stix2.v21.Relationship(created_by_ref=user_id,
                                      source_ref=ind.id,
                                      target_ref=phase_atp.id,
                                      relationship_type='indicates',
                                      object_marking_refs=[tlp])
    mitre_id = "attack-pattern--4b74a1d4-b0e9-4ef1-93f1-14ecc6e2f5b5"
    instance = stix2.v21.Relationship(created_by_ref=user_id,
                                      source_ref=phase_atp.id,
                                      target_ref=mitre_id,
                                      relationship_type='instance-of',
                                      object_marking_refs=[tlp])
    inc_props = {'x_eiq_assigned_to_ref': user_id,
                 'x_eiq_priority': 'High'}
    inc_atp = stix2.v21.AttackPattern(created_by_ref=user_id,
                                      name='INCIDENT',
                                      custom_properties=inc_props,
                                      object_marking_refs=[tlp])
    phase_of = stix2.v21.Relationship(created_by_ref=user_id,
                                      source_ref=phase_atp.id,
                                      target_ref=inc_atp.id,
                                      relationship_type='phase-of',
                                      object_marking_refs=[tlp])
    targets = stix2.v21.Relationship(created_by_ref=user_id,
                                     source_ref=inc_atp.id,
                                     target_ref=target_org,
                                     relationship_type='targets',
                                     object_marking_refs=[tlp])

    objects = [obs1, obs2, obsdata, ind, based, phase_atp, indicate,
               instance, inc_atp, phase_of, targets]

    bundle = json.loads(stix2.v21.Bundle(objects=objects).serialize())
    return bundle['objects'], [phase_atp.id, inc_atp.id]


def make_targeting(user_id, campaign_name, targeted_orgid, atp_id, iset_id=None):

    cam = stix2.v21.Campaign(created_by_ref=user_id,
                             name=campaign_name,
                             object_marking_refs=[stix2.v21.common.TLP_GREEN.id])
    atp_rel = stix2.v21.Relationship(created_by_ref=user_id,
                                     source_ref=cam.id,
                                     target_ref=atp_id,
                                     relationship_type='uses',
                                     object_marking_refs=[stix2.v21.common.TLP_GREEN.id])
    set_rel = stix2.v21.Relationship(created_by_ref=user_id,
                                     source_ref=cam.id,
                                     target_ref=iset_id,
                                     relationship_type='attributed-to',
                                     object_marking_refs=[stix2.v21.common.TLP_GREEN.id])
    target = stix2.v21.Relationship(created_by_ref=user_id,
                                    source_ref=cam.id,
                                    target_ref=targeted_orgid,
                                    relationship_type='targets',
                                    object_marking_refs=[stix2.v21.common.TLP_GREEN.id])
    objects = [cam, atp_rel, set_rel, target]

    bundle = json.loads(stix2.v21.Bundle(objects=objects).serialize())
    return bundle['objects'], cam.id


def make_attribution(user_id, actor_name, iset_id):
    actor = stix2.v21.ThreatActor(created_by_ref=user_id,
                                  name=actor_name,
                                  threat_actor_types=["nation-state"],
                                  object_marking_refs=[stix2.v21.common.TLP_GREEN.id])
    att_rel = stix2.v21.Relationship(created_by_ref=user_id,
                                     source_ref=iset_id,
                                     target_ref=actor.id,
                                     relationship_type='attributed-to',
                                     object_marking_refs=[stix2.v21.common.TLP_GREEN.id])
    objects = [actor, att_rel]
    bundle = json.loads(stix2.v21.Bundle(objects=objects).serialize())
    return bundle['objects'], actor.id


def get_rels(stix_id):
    q_id = stix_id.split('--')[1]

    q = {"query": {"bool": {"should": [
                                {"match": {"source_ref": q_id}},
                                {"match": {"target_ref": q_id}}
    ]}}}

    res = g4i.search(user_id=g4i.identity['id'], index='relationship',
                     _md=False, body=q)

    id_list = []
    for obj in res['hits']['hits']:
        id_list.append(obj['_source']['id'])
        if obj['_source']['source_ref'] == stix_id:
            id_list.append(obj['_source']['target_ref'])
        elif obj['_source']['target_ref'] == stix_id:
            id_list.append(obj['_source']['source_ref'])

    return list(set(id_list))


def get_yara(user_id):
    urls = [
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/Exploit-Kits/EK_Angler.yar",
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/Exploit-Kits/EK_Blackhole.yar",
    ]
    objects = []
    tmp_pattern = "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']"
    for url in urls:
        r = requests.get(url)
        yara_desc = re.search('description = "(.*)"', r.text)
        if yara_desc:
            name = yara_desc.group(1)
        else:
            name = 'HUNT'
        ind = stix2.v21.Indicator(created_by_ref=user_id,
                                  name=name,
                                  pattern_type='yara',
                                  pattern=tmp_pattern,
                                  valid_from=datetime.now(),
                                  indicator_types=['malicious-activity'],
                                  object_marking_refs=[stix2.v21.common.TLP_GREEN.id])
        # q = {'query': {'bool': {'filter': {'bool': {'should': [{'bool': {'must_not': {'exists': {'field': 'revoked'}}}},
        #                                            {'bool': {'must_not': {'match': {'revoked': True}}}}]}},
        #             'must': {'match': {'context': 'os-data-markings'}}}}}
        # res = g4i.search(user_id=user_id, index='marking-definition', body=q)
        # pprint(res)
        ind = json.loads(ind.serialize())
        ind['pattern'] = base64.b64encode(str(r.text).encode())
        print(ind['name'], ind['id'])
        print(g4i.index(user_id=g4i.identity['id'], body=ind))

        id_parts = ind['id'].split('--')
        _index = id_parts[0]
        _id = id_parts[1]

        obj_fields = list(ind.keys())
        fields = [field for field in obj_fields if field not in admin_fields]

        q = {"query": {"more_like_this": {"fields": fields,
                                          "like": {"_index": _index, "_id": _id}}}}
        # pprint(q)
        res = g4i.search(user_id=user_id, index='intel', body=q)
        pprint(res)


def capture_nodes(org_id):
    # Get all nodes that are configured on a plgx server and add them to the
    #  knowledge base. Return a list of possible tags to select from for
    #  Rule/Pack deployment.

    # Vanilla plgx server setup...
    domain = '127.0.0.1'
    username = 'admin'
    password = 'admin'
    plgx = PolylogyxApi(domain=domain, username=username, password=password)

    # Get nodes and create identities for them
    nodes = plgx.get_nodes()

    all_tags = []
    pii_dm = g4i.pii_marking['id']
    for node in nodes['results']['data']:
        if not node['is_active']:
            continue
        all_tags += node['tags']
        # Create new identity object for node
        stix_node = stix2.v21.Identity(created_by_ref=org_id,
                                       id='identity--' + node['node_key'],
                                       identity_class='system',
                                       labels=node['tags'],
                                       name=node['display_name'],
                                       object_marking_refs=[pii_dm])
        # Create 'deployed-by' relationship from node to org
        node_rel = stix2.v21.Relationship(created_by_ref=org_id,
                                          relationship_type='deployed-by',
                                          source_ref=stix_node.id,
                                          target_ref=org_id,
                                          object_marking_refs=[pii_dm])
        # Store new objects to knowledge base
        print(g4i.index(user_id=g4i.identity['id'],
                        body=json.loads(stix_node.serialize())))
        print(g4i.index(user_id=g4i.identity['id'],
                        body=json.loads(node_rel.serialize())))

    # Return the list of all tags to be used in rule deployment
    return all_tags


def deploy_packs(threat_id, tags):
    # Get data from graph walk down to Indicators:
    # Note, this uses g4i molecule walk which requires some post-filtering.
    #  Better to have 1-shot query if possible.
    res = g4i.get_molecule(
        user_id=g4i.identity['id'],
        stix_ids=[threat_id],
        schema_name="mitre",
        objs=True,
        pivot=False)
    if not res:
        return False

    # Vanilla plgx server setup...
    domain = '127.0.0.1'
    username = 'admin'
    password = 'admin'
    plgx = PolylogyxApi(domain=domain, username=username, password=password)

    # Post-filtering and deploy each pack...
    out = []
    for hit in hits_from_res(res):
        if hit['type'] != 'indicator':
            continue
        if hit['pattern_type'] != 'osquery-pack':
            continue
        # Add tags which is the way to tell plgx server to deploy to nodes
        #  that also have that tag.
        new_pack = json.loads(hit['pattern'])
        new_pack['tags'] = tags
        new_pack = json.dumps(new_pack)

        headers = {'x-access-token': plgx.AUTH_TOKEN,
                   'content-type': 'application/json'}
        url = plgx.base + "/distributed/add"
        try:
            response = requests.post(
                url, json=new_pack, headers=headers,
                verify=False, timeout=30)
        except requests.RequestException as e:
            out.append(dict(error=str(e)))
        out.append(plgx._return_response_and_status_code(response))

    return out


def data_dump():
    stats = {}
    count = 0
    q = {"query": {"match_all": {}}}
    for hit in helpers.scan(client=g4i, index='intel', query=q, user_id=g4i.identity['id']):
        try:
            with open('./cti-data/' + hit['_source']['type'] + '/' + hit['_source']['id'] + '.json', 'w') as outfile:
                json.dump(hit['_source'], outfile)
        except FileNotFoundError:
            os.mkdir('./cti-data/' + hit['_source']['type'])
            with open('./cti-data/' + hit['_source']['type'] + '/' + hit['_source']['id'] + '.json', 'w') as outfile:
                json.dump(hit['_source'], outfile)
        try:
            stats[hit['_source']['type']] += 1
        except KeyError:
            stats[hit['_source']['type']] = 1
        count += 1

    print(count)
    pprint(stats)
    return True


def jacek_search(s):
    r = r'\S{3,32}--[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}'

    ids = re.findall(r, s)
    q_should = []
    for _id in ids:
        if _id.split('--')[0] == 'relationship':
            continue
        q_should.append({"match": {"id": _id.split('--')[1]}})
    q = {"query": {"bool": {"should": q_should}}}
    return g4i.real_search(index='intel', body=q)


def main():

    # tables = g4i.get_tables('/Users/cobsec/git/osquery/specs')

    # with open('osquery_schema.json', 'w') as outfile:
    #     json.dump(tables, outfile)

    # print(g4i.store_core_data())
    # print(g4i.data_primer())
    # print(g4i.get_osquery('/Users/cobsec/git/osquery-attck'))
    # print(g4i.get_sigma('/Users/cobsec/git/sigma/rules'))

    # print(g4i.data_dump())

    s1 = '''relationship--87231371-e005-44ab-9b66-1954615f2a7e: malware--310f437b-29e7-4844-848c-7220868d074a revoked-by malware--b42378e0-f147-496f-992a-26a49705395b
relationship--3680408d-e56e-4d68-a74d-2678093ed53f: intrusion-set--9559ecaf-2e75-48a7-aee8-9974020bc772 revoked-by intrusion-set--17862c7d-9e60-48a0-b48e-da4dc4c3f6b0
relationship--632ca9a0-a9f3-4b27-96e1-9fcb8bab11cb: intrusion-set--68ba94ab-78b8-43e7-83e2-aed3466882c6 revoked-by intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d
relationship--53364899-1ea5-47fa-afde-c210aed64120: intrusion-set--8a831aaa-f3e0-47a3-bed8-a9ced744dd12 uses malware--c41a8b7c-3e42-4eee-b87d-ad8a100ee878
relationship--73ca1e9c-27c8-4feb-8792-6c2cbb3f64f7: grouping--db41c024-7869-4200-9c4c-4a07b2d09de7 derived-from grouping--73a0f925-468b-4cbd-aeef-9c66ceae4067
relationship--743ab343-e592-410c-bbd8-4bbfe9425a62: indicator--1aa6893f-fe4b-419d-aef8-cca9a957cc7f derived-from indicator--a3dd496b-4359-4657-a90b-640cb93b3c64
relationship--1305f718-a339-4c0d-ab8e-9a7760fcbd48: indicator--837d0fac-507d-41d4-a008-a8164a6483ba derived-from indicator--1aa6893f-fe4b-419d-aef8-cca9a957cc7f
relationship--e179b775-7920-4514-b291-d8c3850b4100: indicator--1aa6893f-fe4b-419d-aef8-cca9a957cc7f derived-from indicator--32aaeec7-912b-4c85-a646-f603a78f5251
relationship--3a49d7a4-88e6-495f-8428-95ee6b7a52b9: indicator--8c96cc34-c8b0-45ea-afbc-10d33101c0e8 derived-from indicator--2618e60e-51c0-4e21-ac9d-6226736028eb
relationship--e8664e08-18bc-4427-8783-8195c3e9f41c: indicator--7c1a44a5-2b9f-41cf-aeb0-ab0d2fc839c7 derived-from indicator--ec48a59e-1db5-48f4-ab1c-e80d154283fb
relationship--b6021aac-a12d-401d-b4ab-2fd2ec0cef18: indicator--9caee33c-7dda-4906-abfd-268b18a2a961 derived-from indicator--ec48a59e-1db5-48f4-ab1c-e80d154283fb
relationship--05299410-15bb-4985-b0dd-fd55a321439d: indicator--13819ea3-6e34-4aaf-a4e9-d2c9cd7f611e derived-from indicator--ec48a59e-1db5-48f4-ab1c-e80d154283fb
relationship--29ba3877-ad62-4ccb-8b28-2fc76060464d: indicator--d2b36ee0-1780-4490-b188-b0ca5c45965a derived-from indicator--8c96cc34-c8b0-45ea-afbc-10d33101c0e8
relationship--90840469-8b66-47bc-b283-68318623fe71: indicator--8c96cc34-c8b0-45ea-afbc-10d33101c0e8 derived-from indicator--bbd11da6-48d5-4d5b-a6fa-6ffb0f6dc2f2
relationship--8c6fdaf6-ca8c-4b20-8e70-19d55f162a3a: indicator--2f21d2b9-b1f5-413e-aab6-a194f97a3ff0 derived-from indicator--13819ea3-6e34-4aaf-a4e9-d2c9cd7f611e
relationship--134e398e-a782-4a10-a15d-73f7d7b95d8e: indicator--13819ea3-6e34-4aaf-a4e9-d2c9cd7f611e derived-from indicator--2b8ef778-c1fe-4dc0-af8a-de2c246ac101
relationship--1c4efe1f-6e8a-4eac-92f2-dd72bc686fd9: indicator--ba16060a-e5f8-4967-b9c1-cb1430870a3b derived-from indicator--7c1a44a5-2b9f-41cf-aeb0-ab0d2fc839c7
relationship--5f9ce4b8-b044-486a-aa23-22c57a3835cd: indicator--7c1a44a5-2b9f-41cf-aeb0-ab0d2fc839c7 derived-from indicator--2b8ef778-c1fe-4dc0-af8a-de2c246ac101
relationship--f4ad18de-46da-4c0d-8f07-4e65beab70fd: indicator--5562caf3-d474-4644-aabd-66f95d77a3d9 derived-from indicator--a581e814-484e-497b-ae0d-7ea040fee56a
relationship--1d18940e-200e-4999-84bc-aab80cbd2ad7: indicator--898ba28c-5079-46b1-8e57-6163fca251ea derived-from indicator--5562caf3-d474-4644-aabd-66f95d77a3d9
relationship--0e48ce21-529e-49e6-989d-7f13cdcef794: indicator--5562caf3-d474-4644-aabd-66f95d77a3d9 derived-from indicator--75ed9af2-65ad-40ab-a470-8e7a3f026ce0
relationship--5136f806-400c-4497-9548-04479868dbbc: indicator--6dc428f3-bdf9-43da-adb1-640bc7ab4430 derived-from indicator--9caee33c-7dda-4906-abfd-268b18a2a961
relationship--66808b05-c20b-44bd-9205-9d815c4b294c: indicator--9caee33c-7dda-4906-abfd-268b18a2a961 derived-from indicator--2b8ef778-c1fe-4dc0-af8a-de2c246ac101'''

    s2 = '''relationship--87231371-e005-44ab-9b66-1954615f2a7e: malware--310f437b-29e7-4844-848c-7220868d074a revoked-by malware--b42378e0-f147-496f-992a-26a49705395b
relationship--3680408d-e56e-4d68-a74d-2678093ed53f: intrusion-set--9559ecaf-2e75-48a7-aee8-9974020bc772 revoked-by intrusion-set--17862c7d-9e60-48a0-b48e-da4dc4c3f6b0
relationship--632ca9a0-a9f3-4b27-96e1-9fcb8bab11cb: intrusion-set--68ba94ab-78b8-43e7-83e2-aed3466882c6 revoked-by intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d
relationship--53364899-1ea5-47fa-afde-c210aed64120: intrusion-set--8a831aaa-f3e0-47a3-bed8-a9ced744dd12 uses malware--c41a8b7c-3e42-4eee-b87d-ad8a100ee878
relationship--73ca1e9c-27c8-4feb-8792-6c2cbb3f64f7: grouping--db41c024-7869-4200-9c4c-4a07b2d09de7 derived-from grouping--73a0f925-468b-4cbd-aeef-9c66ceae4067
relationship--3a49d7a4-88e6-495f-8428-95ee6b7a52b9: indicator--8c96cc34-c8b0-45ea-afbc-10d33101c0e8 derived-from indicator--2618e60e-51c0-4e21-ac9d-6226736028eb
relationship--b6021aac-a12d-401d-b4ab-2fd2ec0cef18: indicator--9caee33c-7dda-4906-abfd-268b18a2a961 derived-from indicator--ec48a59e-1db5-48f4-ab1c-e80d154283fb
relationship--29ba3877-ad62-4ccb-8b28-2fc76060464d: indicator--d2b36ee0-1780-4490-b188-b0ca5c45965a derived-from indicator--8c96cc34-c8b0-45ea-afbc-10d33101c0e8
relationship--90840469-8b66-47bc-b283-68318623fe71: indicator--8c96cc34-c8b0-45ea-afbc-10d33101c0e8 derived-from indicator--bbd11da6-48d5-4d5b-a6fa-6ffb0f6dc2f2
relationship--f4ad18de-46da-4c0d-8f07-4e65beab70fd: indicator--5562caf3-d474-4644-aabd-66f95d77a3d9 derived-from indicator--a581e814-484e-497b-ae0d-7ea040fee56a
relationship--1d18940e-200e-4999-84bc-aab80cbd2ad7: indicator--898ba28c-5079-46b1-8e57-6163fca251ea derived-from indicator--5562caf3-d474-4644-aabd-66f95d77a3d9
relationship--0e48ce21-529e-49e6-989d-7f13cdcef794: indicator--5562caf3-d474-4644-aabd-66f95d77a3d9 derived-from indicator--75ed9af2-65ad-40ab-a470-8e7a3f026ce0
relationship--5136f806-400c-4497-9548-04479868dbbc: indicator--6dc428f3-bdf9-43da-adb1-640bc7ab4430 derived-from indicator--9caee33c-7dda-4906-abfd-268b18a2a961
relationship--66808b05-c20b-44bd-9205-9d815c4b294c: indicator--9caee33c-7dda-4906-abfd-268b18a2a961 derived-from indicator--2b8ef778-c1fe-4dc0-af8a-de2c246ac101'''

    res1 = jacek_search(s1)
    res2 = jacek_search(s2)

    ids1 = []
    for hit in hits_from_res(res1):
        ids1.append(hit['id'])
    ids2 = []
    for hit in hits_from_res(res2):
        ids2.append(hit['id'])

    already_done = []
    still_missing = []
    for _id in ids2:
        if _id in ids1:
            already_done.append(_id)
        else:
            still_missing.append(_id)

    print('These were already done in the first run:')
    for _id in already_done:
        print(_id)
    print('...and these are the ones that are still missing, so needs more work:')
    for _id in still_missing:
        print(_id)

    s3 = '''These were already done in the first run:
indicator--5562caf3-d474-4644-aabd-66f95d77a3d9
indicator--8c96cc34-c8b0-45ea-afbc-10d33101c0e8
indicator--9caee33c-7dda-4906-abfd-268b18a2a961
indicator--ec48a59e-1db5-48f4-ab1c-e80d154283fb
indicator--2b8ef778-c1fe-4dc0-af8a-de2c246ac101
...and these are the ones that are still missing, so needs more work:
indicator--a581e814-484e-497b-ae0d-7ea040fee56a
indicator--75ed9af2-65ad-40ab-a470-8e7a3f026ce0
indicator--898ba28c-5079-46b1-8e57-6163fca251ea
indicator--bbd11da6-48d5-4d5b-a6fa-6ffb0f6dc2f2
indicator--d2b36ee0-1780-4490-b188-b0ca5c45965a'''

    res = jacek_search(s3)
    count = 0
    objects = []
    for hit in hits_from_res(res):
        objects.append(hit)
        print(hit)
        count += 1
    print(count)
    bundle = {"type": "bundle",
              "id": get_deterministic_uuid(prefix='bundle--',
                                           seed='fuck-bundles3'),
              "objects": objects}
    with open('cti-extra2.json', 'w') as outfile:
        json.dump(bundle, outfile)

    # # Make some organisation objects for the users/org:
    # objects, ids = make_org(username1="User1",
    #                         username2="User2",
    #                         orgname="Acme Corps")
    # # Objects are in objects, org_id is the only id we need...
    # org_id = ids[0]

    # available_tags = capture_nodes(org_id=org_id)

    # # Pick a tag to deploy new rules to...
    # deploy_tag = available_tags[0]

    # # Pick a threat to deploy rules for...
    # pteranodon = 'malware--5f9f7648-04ba-4a9f-bb4c-2a13e74572bd'

    # print(deploy_packs(threat_id=pteranodon, tags=[deploy_tag]))

                
                # out[ref['external_id']] = [obj['id'], obj['name']]
    # pprint(out)



    # print(deploy_packs(pteranodon, ['all']))

    # # Make org 1:
    # org1, users1 = make_org(username1="User1",
    #                         username2="User2",
    #                         orgname="Acme Corps")

    # print(org1)
    # print(users1)

    # print(g4i.index_objects(user_id=g4i.identity['id'], objects=org1,
    #                         refresh='wait_for'))

    # res = make_sighting(ind_id='indicator--a6855f67-9494-4fd6-8384-80c5d1b52b8c')
    # print(res)

    # # with open('sighting.json', 'w') as outfile:
    # #     json.dump(res, outfile)

    # print(g4i.index_objects(user_id=users1[1], objects=res['objects'],
    #                         refresh='wait_for'))


    # q = {"query": {"match_all": {}}}

    # intel_res = g4i.search(user_id='identity--07d648ff-0aeb-4ccd-8aa5-8ac18d27f312',
    #                        index='intel', body=q)
    # # tactic_res = g4i.search(user_id='identity--87864f4b-839d-428f-96f9-455b9f00d445',
    # #                         index='x-mitre-tactic', body=q)
    # # matrix_res = g4i.search(user_id='identity--87864f4b-839d-428f-96f9-455b9f00d445',
    # #                         index='x-mitre-matrix', body=q)

    # out = []
    # for obj in hits_from_res(intel_res):
    #     out.append(obj)

    # bundle = {"type": "bundle",
    #           "id": get_deterministic_uuid(prefix='bundle--',
    #                                        seed='fuck-bundles'),
    #           "objects": out}
    # with open('out.json', 'w') as outfile:
    #     json.dump(bundle, outfile)






    # ind = stix2.v21.Indicator(created_by_ref='identity--ce5be1f3-92b4-4a92-a42a-706bf061e2c7',
    #                           )

    # rel = stix2.v21.Relationship(created_by_ref='identity--ce5be1f3-92b4-4a92-a42a-706bf061e2c7',
    #                              target_ref='observed-data--ecbf04c1-97eb-44cc-b690-d7e1303b4558',
    #                              source_ref=ind.id)

    # user_id = 'identity--ce5be1f3-92b4-4a92-a42a-706bf061e2c7'

    # # obs = stix2.v21.URL(value='www.badthing.com',
    # #                     id='url--f2b7580e-487f-4b23-a0f8-7bdef90be36f')

    # # print(g4i.get(index='url', id='f2b7580e-487f-4b23-a0f8-7bdef90be36f'))

    # res = g4i.get_events(user_id=user_id)
    # pprint(res)

    # print(obs)
    # print(g4i.index(user_id=user_id, body=obs))

    # res = g4i.get(index='stix-perc',
    #               id='percolator--741d4b93-54be-4b4f-a329-9d128bef25d9')

    # pprint(res)

    # res = g4i.get_free_text(user_id=g4i.identity['id'], phrase='Secret')
    # pprint(res)

    # assertion = {
    #     "id": get_deterministic_uuid(prefix='assertion--'),
    #     "type": "assertion",
    #     "in_object_refs": ["relationship--41414141-4141-4141-4141-414141414141"],
    #     "out_object_refs": ["relationship--42424242-4242-4242-4242-424242424242"]
    # }
    # print(json.dumps(assertion))

    # mitre_atp_id = "attack-pattern--4b74a1d4-b0e9-4ef1-93f1-14ecc6e2f5b5"

    # print(g4i.get_phase_count(user_id=g4i.identity['id'],
    #                           mitre_atp_id=mitre_atp_id))

    # iset = "malware--5f9f7648-04ba-4a9f-bb4c-2a13e74572bd"

    # res = g4i.get_molecule(user_id=g4i.identity['id'],
    #                        stix_ids=[iset],
    #                        schema_name="capabilities",
    #                        objs=True)

    # pprint(res)
    # bundle = {"type": "bundle",
    #           "id": get_deterministic_uuid(prefix='bundle--',
    #                                        seed='fuck-bundles'),
    #           "objects": res}
    # with open('gamaredon.json', 'w') as outfile:
    #     json.dump(bundle, outfile)

    # get_yara(user_id=g4i.identity['id'])

    # mitre_atp = "tool--aafea02e-ece5-4bb2-91a6-3bf8c7f38a39"

    # res = g4i.get_molecule(user_id=g4i.identity['id'],
    #                        stix_ids=[mitre_atp],
    #                        schema_name='mitre',
    #                        objs=True)

    # # pprint(res)
    # bundle = {"type": "bundle",
    #           "id": get_deterministic_uuid(prefix='bundle--',
    #                                        seed='fuck-bundles'),
    #           "objects": res}
    # with open('mitre.json', 'w') as outfile:
    #     json.dump(bundle, outfile)

    # os_group = "grouping--5de44717-4f2a-42b9-9bdf-a1ea101f7d6e"
    # res = g4i.get_object(user_id=g4i.identity['id'],
    #                      obj_id=os_group)
    # pprint(res)

    # stix_id = "attack-pattern--2f8d3c0c-084f-4202-b988-5d756faf6185"

    # res = g4i.get_molecule(user_id=g4i.identity['id'],
    #                        stix_ids=[stix_id],
    #                        schema_name='phase',
    #                        pivot=True)
    # pprint(res)

    # atp_id = "attack-pattern--6aac77c4-eaf2-4366-8c13-ce50ab951f38"
    # iset_id = "intrusion-set--06a11b7e-2a36-47fe-8d3e-82c265df3258"
    # org_id = "identity--5b29a274-d021-4a38-b819-6263a3e9286d"

    # # Do some targeting analysis...
    # cam, cam_id = make_targeting(user_id=g4i.identity['id'],
    #                              campaign_name="CAMPAIGN",
    #                              targeted_orgid=org_id,
    #                              atp_id=atp_id,
    #                              iset_id=iset_id)

    # # Do some attribution analysis...
    # acto1, actor_i1 = make_attribution(user_id=g4i.identity['id'],
    #                                    actor_name="Zeus",
    #                                    iset_id=iset_id)

    # acto2, actor_i2 = make_attribution(user_id=g4i.identity['id'],
    #                                    actor_name="ZeuS Group",
    #                                    iset_id=iset_id)

    # acto3, actor_i3 = make_attribution(user_id=g4i.identity['id'],
    #                                    actor_name="Feodo",
    #                                    iset_id=iset_id)

    # objects = cam + acto1 + acto2 + acto3

    # print(g4i.index_objects(user_id=g4i.identity['id'], objects=objects,
    #                         refresh='wait_for'))

    # # obj_id = "threat-actor--bb0a8c50-2b84-450c-ab36-5b9527dbc23f"
    # id_parts = actor_i1.split('--')
    # _index = id_parts[0]
    # _id = id_parts[1]

    # atp_obj = g4i.get_object(user_id=g4i.identity['id'], obj_id=actor_i1)

    # obj_fields = list(atp_obj.keys())

    # fields = [field for field in obj_fields if field not in admin_fields]

    # q = {"query": {"more_like_this": {"fields": fields,
    #                                   "like": {"_index": _index, "_id": _id},
    #                                   "min_term_freq": 1}}}

    # res = g4i.search(user_id=g4i.identity['id'], index=_index, body=q, size=10)

    # pprint(res)
    # print(fields)
    # pprint(atp_obj)

    # user_id = "identity--8194aa4e-8f4f-4acb-9a23-55191cf39dde"
    # phase_id = "attack-pattern--581829e5-4066-4c5e-bf8c-7f24b55809fe"

    # print('Get phase...')
    # start = time.time()
    # res = g4i.get_molecule(user_id=user_id,
    #                        stix_ids=[phase_id],
    #                        schema_name='phase',
    #                        objs=True,
    #                        pivot=False)
    # end = time.time()
    # pprint(res)
    # print(end-start)

    # author = "identity--6d9f5924-fe28-4579-853b-0e3d77536ad9"
    # recipient = "identity--ed059e4f-1810-4f16-9cb5-4a8ba7dc9333"

    # print(g4i.set_tlpplus(user_id=author,
    #                       md_name="Super Secret Distro List!!!",
    #                       tlp_marking_def_ref=stix2.v21.common.TLP_RED.id,
    #                       distribution_refs=[author, recipient]))

    # time.sleep(2)

    # print(g4i.set_tlpplus(user_id=author,
    #                       md_name="Super Secret Distro List!!!",
    #                       tlp_marking_def_ref=stix2.v21.common.TLP_RED.id,
    #                       distribution_refs=[author, recipient]))

    # time.sleep(2)

    # print(g4i.set_tlpplus(user_id=author,
    #                       md_name="Banter network...",
    #                       tlp_marking_def_ref=stix2.v21.common.TLP_RED.id,
    #                       distribution_refs=[author, recipient]))

    # mol = g4i.get_molecule(
    #        user_id=g4i.identity['id'],
    #        stix_ids=["attack-pattern--fff235c8-6c22-415c-ab72-5abb7b6de0ce"],
    #        schema_name='phase',
    #        objs=True,
    #        pivot=False)

    # pprint(mol)

    # q = {"query": {"match_all": {}}}
    # res = g4i.search(user_id=g4i.identity['id'], index='marking-definition',
    #                  body=q)
    # pprint(res)

    # res = g4i.indices.get_alias(name="intel--d9482fd5-eea2-4416-b82f-d15fc03e9b57--19081916")
    # pprint(res)

    #   md_obj = {
    #   "definition_type": "tlp-plus",
    #   "definition": {
    #     "tlp_marking_def_ref": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    #     "distribution_refs": [
    #       "identity--279707f3-fc49-40a6-b7c4-b4a58e235804",
    #       "identity--01f471c6-f620-4733-925b-4bb8bb7a33ac"
    #     ]
    #   },
    #   "id": "marking-definition--1bd25494-8cbb-42d5-aa78-e7d332a253d4",
    #   "created_by_ref": "identity--01f471c6-f620-4733-925b-4bb8bb7a33ac",
    #   "type": "marking-definition",
    #   "spec_version": "2.1",
    #   "created": "2019-08-19T11:25:17.684909Z"
    # }

    #   res = g4i.update_md(md_obj=md_obj)
    #   print(res)

    # res = g4i.get_events(user_id="identity--5710089b-bec8-4913-b674-bf7c6be221ae")
    # pprint(res)

    # stix_id = "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
    # related_ids = get_rels(stix_id=stix_id)

    # tmp_ids = related_ids[:]
    # for _id in tmp_ids:
    #     sub_rels = get_rels(stix_id=_id)
    #     related_ids += sub_rels

    # objects = g4i.get_objects(user_id=g4i.identity['id'], obj_ids=related_ids)

    # bundle = {"type": "bundle",
    #           "id": get_deterministic_uuid(prefix='bundle--',
    #                                        seed='fuck-bundles'),
    #           "objects": objects}
    # with open('mitre-big.json', 'w') as outfile:
    #     json.dump(bundle, outfile)

    # # Version testing
    # objects = []
    # for i in range(5):
    #     inc_atp = stix2.v21.AttackPattern(name='INCIDENT--' + str(i),
    #                                       id="attack-pattern--c3df754e-997b-4cf9-97d4-70feb3120851")
    #     objects.append(inc_atp)

    # bundle = json.loads(stix2.v21.Bundle(objects=objects).serialize())

    # g4i.index_objects(user_id="identity--084bcd40-a2ed-4420-84db-04444bd0e763",
    #                   objects=bundle['objects'])

    # print(g4i.store_core_data())
    # print(g4i.data_primer())

    # # Make org 1:
    # org1, users1 = make_org(username1="User1",
    #                         username2="User2",
    #                         orgname="Acme Corps")
    # # Event, phase and incident (green)
    # green_inc1, inc_ids1 = make_incident(user_id=users1[1],
    #                                      target_org=users1[0],
    #                                      tlp='green')

    # # Event, phase and incident (white)
    # green_inc2, inc_ids2 = make_incident(user_id=users1[2],
    #                                      target_org=users1[0],
    #                                      tlp='white')

    # atp_id = "attack-pattern--6aac77c4-eaf2-4366-8c13-ce50ab951f38"
    # iset_id = "intrusion-set--06a11b7e-2a36-47fe-8d3e-82c265df3258"

    # # Do some targeting analysis...
    # cam, cam_id = make_targeting(user_id=users1[1],
    #                              campaign_name="CAMPAIGN",
    #                              targeted_orgid=users1[0],
    #                              atp_id=atp_id,
    #                              iset_id=iset_id)

    # # Do some attribution analysis...
    # actor, actor_id = make_attribution(user_id=users1[1],
    #                                    actor_name="THREAT ACTOR",
    #                                    iset_id=iset_id)

    # # Make org 2:
    # org2, users2 = make_org(username1="User1",
    #                         username2="User2",
    #                         orgname="Arkham Ventures")
    # # Event, phase and incident (red)
    # red_inc1, inc_ids3 = make_incident(user_id=users2[1],
    #                                    target_org=users2[0],
    #                                    tlp='red',
    #                                    tlp_dist=[users1[1], users2[1]])

    # objects = org1 + green_inc1 + green_inc2 + org2 + red_inc1 + cam + actor
    # # bundle = {"type": "bundle",
    # #           "id": get_deterministic_uuid(prefix='bundle--',
    # #                                        seed='fuck-bundles'),
    # #           "objects": objects}
    # # with open('data.json', 'w') as outfile:
    # #     json.dump(bundle, outfile)

    # print('Storing sample data...')
    # start = time.time()
    # print(g4i.index_objects(user_id=users1[1], objects=objects,
    #                         refresh='wait_for'))
    # end = time.time()
    # print(end-start)

    # # REGISTER A PERCOLATOR INDEX FOR ALL DOCUMENT TYPES...
    # mappings = g4i.indices.get_mapping(index="_all")
    # master_map = {}
    # for mapping in mappings:
    #     if mapping[:1] == '.':
    #         continue
    #     master_map.update(mappings[mapping]['mappings']['properties'])
    # master_map['core'] = {'type': 'percolator'}
    # master_map['ext'] = {'type': 'percolator'}
    # master_map = {
    #     "settings": {
    #         "analysis": {
    #             "analyzer": {
    #                 "stixid_analyzer": {
    #                     "tokenizer": "id_split"
    #                 }
    #             },
    #             "tokenizer": {
    #                 "id_split": {
    #                     "type": "pattern",
    #                     "pattern": "--"
    #                 }
    #             }
    #         }

    #     },
    #     'mappings': {'properties': master_map}}
    # pprint(master_map)

    # print(g4i.indices.create(index="stix-perc", body=master_map, ignore=400))

    # # REGISTER A PERCOLATOR QUERY FOR A MOLECULE...
    # inc_mol = {
    #     "core": {"bool": {"should": [
    #         {"bool": {"must": [
    #             {"match": {"type": "attack-pattern"}},
    #             {"match": {"x_eiq_assigned_to_ref": "identity--"}},
    #             {"exists": {"field": "x_eiq_priority"}}
    #         ]}},
    #         {"bool": {"must": [
    #             {"match": {"type": "identity"}},
    #             {"bool": {"should": [
    #                 {"match": {"identity_class": "individual"}},
    #                 {"match": {"identity_class": "system"}},
    #                 {"match": {"identity_class": "organization"}}
    #             ]}}
    #         ]}},
    #         {"bool": {"must": [
    #             {"match": {"type": "relationship"}},
    #             {"match": {"relationship_type": "targets"}},
    #             {"match": {"source_ref": "attack-pattern--"}},
    #             {"match": {"target_ref": "identity--"}}
    #         ]}}
    #     ]}},
    #     "ext": {"bool": {"should": [
    #         {"bool": {"must": [
    #             {"match": {"type": "relationship"}},
    #             {"match": {"relationship_type": "phase-of"}},
    #             {"match": {"source_ref": "attack-pattern--"}},
    #             {"match": {"target_ref": "attack-pattern--"}}
    #         ]}}
    #     ]}}
    # }

    # print(g4i.index(user_id=g4i.identity['id'], index='stix-perc',
    #                 id=get_deterministic_uuid(prefix='percolator--'),
    #                 body=inc_mol, refresh='wait_for'))

    # # TEST A KNOWN HIT DOC AGAINST THE PERC QUERY...
    # for idref in inc_ids1:
    #     print(idref)
    #     idparts = idref.split('--')
    #     _index = idparts[0]
    #     _id = idparts[1]

    #     p = {"query": {"constant_score": {"filter": {"percolate": {"field": "core", "index": _index,
    #                                  "id": _id, "version": 1}}}}}

    #     start = time.time()
    #     res = g4i.real_search(index='stix-perc', body=p,
    #                           filter_path=['hits.hits._id'])
    #     end = time.time()
    #     pprint(res)
    #     print(end-start)

    # print('Get org1 info...')
    # start = time.time()
    # res = g4i.get_molecule(user_id=users1[1],
    #                        stix_ids=[users1[0]],
    #                        schema_name='org',
    #                        objs=True,
    #                        pivot=True)
    # end = time.time()
    # pprint(res)
    # print(end-start)

    # print('Get inc1...')
    # start = time.time()
    # res = g4i.get_molecule(user_id=users1[1],
    #                        stix_ids=[inc_ids1[1]],
    #                        schema_name='incident',
    #                        objs=True,
    #                        pivot=False)
    # end = time.time()
    # pprint(res)
    # print(end-start)

    # print('Try to get red inc when not on distro...')
    # start = time.time()
    # res = g4i.get_molecule(user_id=users1[2],
    #                        stix_ids=[inc_ids3[1]],
    #                        schema_name='incident',
    #                        objs=True,
    #                        pivot=False)
    # end = time.time()
    # pprint(res)
    # print(end-start)

    # print('Get remediations for an attack pattern...')
    # start = time.time()
    # res = g4i.get_molecule(user_id=users1[2],
    #                        stix_ids=["attack-pattern--4b74a1d4-b0e9-4ef1-93f1-14ecc6e2f5b5"],
    #                        schema_name='remediation',
    #                        objs=True,
    #                        pivot=False)
    # end = time.time()
    # pprint(res)
    # print(end-start)

    # print('Get MC-specific incident format...')
    # start = time.time()
    # res = g4i.get_incidents(user_id=users1[1],
    #                         focus='my_org')

    # user_id = 'identity--e10f7a0f-ef60-4ba6-a34e-3fb20849cea5'
    # event_id = 'observed-data--438aa167-dc89-4b8d-8042-89a724b9a114'
    # atp_id = 'malware--5f9f7648-04ba-4a9f-bb4c-2a13e74572bd'

    # res = g4i.get_incidents(user_id=user_id,
    #                         focus='all')

    # res = g4i.get_molecule(user_id=user_id, stix_ids=[event_id],
    #                                 schema_name='event', pivot=False,
    #                                 objs=True)

    # res = g4i.get_events(user_id=user_id)

    # res = g4i.get_molecule(
    #         user_id=user_id,
    #         stix_ids=[atp_id],
    #         schema_name="capabilities",
    #         objs=True,
    #         pivot=False)

    # pprint(res)

    # out = []
    # for obj in hits_from_res(res):
    #     out.append(obj)
    # print(out)

    # end = time.time()
    # pprint(res)
    # print(end-start)

    # print('Get targeting of campaign...')
    # start = time.time()
    # res = g4i.get_molecule(user_id=users1[2],
    #                        stix_ids=[cam_id],
    #                        schema_name='targeting',
    #                        objs=True,
    #                        pivot=False)
    # end = time.time()
    # pprint(res)
    # print(end-start)

    # print('Get attribution of intrusion set...')
    # start = time.time()
    # res = g4i.get_molecule(user_id=users1[2],
    #                        stix_ids=[actor_id],
    #                        schema_name='attribution',
    #                        objs=True,
    #                        pivot=False)
    # end = time.time()
    # pprint(res)
    # print(end-start)


if __name__ == '__main__':
    main()
