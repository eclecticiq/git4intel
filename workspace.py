import git4intel
import stix2
import json
from slugify import slugify
from pprint import pprint
import random
import uuid
from datetime import datetime
import time
import sys

g4i = git4intel.Client('localhost:9200')

admin_fields = [
    'spec_version',
    'id',
    'created',
    'modified',
    'created_by_ref',
    'revoked',
    'confidence',
    'lang',
    'object_marking_refs',
    'granular_markings',
    'defanged',
    'external_references'
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


def main():

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

    # obj_id = "intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662"
    # id_parts = obj_id.split('--')
    # _index = id_parts[0]
    # _id = id_parts[1]

    # atp_obj = g4i.get_object(user_id=g4i.identity['id'], obj_id=obj_id)

    # obj_fields = list(atp_obj.keys())

    # fields = [field for field in obj_fields if field not in admin_fields]

    # q = {"query": {"more_like_this": {"fields": fields,
    #                                   "like": {"_index": _index, "_id": _id}}}}

    # res = g4i.search(user_id=g4i.identity['id'], index=_index, body=q, size=10)

    # pprint(res)

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
    # with open('mitre.json', 'w') as outfile:
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

    print(g4i.store_core_data())
    print(g4i.data_primer())

    # Make org 1:
    org1, users1 = make_org(username1="User1",
                            username2="User2",
                            orgname="Acme Corps")
    # Event, phase and incident (green)
    green_inc1, inc_ids1 = make_incident(user_id=users1[1],
                                         target_org=users1[0],
                                         tlp='green')
    # Event, phase and incident (white)
    green_inc2, inc_ids2 = make_incident(user_id=users1[2],
                                         target_org=users1[0],
                                         tlp='white')

    # Make org 2:
    org2, users2 = make_org(username1="User1",
                            username2="User2",
                            orgname="Arkham Ventures")
    # Event, phase and incident (red)
    red_inc1, inc_ids3 = make_incident(user_id=users2[1],
                                       target_org=users2[0],
                                       tlp='red',
                                       tlp_dist=[users1[1], users2[1]])

    objects = org1 + green_inc1 + green_inc2 + org2 + red_inc1
    bundle = {"type": "bundle",
              "id": get_deterministic_uuid(prefix='bundle--',
                                           seed='fuck-bundles'),
              "objects": objects}
    with open('data.json', 'w') as outfile:
        json.dump(bundle, outfile)

    print('Storing sample data...')
    start = time.time()
    print(g4i.index_objects(user_id=users1[1], objects=objects,
                            refresh='wait_for'))
    end = time.time()
    print(end-start)

    print('Get org1 info...')
    start = time.time()
    res = g4i.get_molecule(user_id=users1[1],
                           stix_ids=[users1[0]],
                           schema_name='org',
                           objs=True,
                           pivot=True)
    end = time.time()
    pprint(res)
    print(end-start)

    print('Get inc1...')
    start = time.time()
    res = g4i.get_molecule(user_id=users1[1],
                           stix_ids=[inc_ids1[1]],
                           schema_name='incident',
                           objs=True,
                           pivot=False)
    end = time.time()
    pprint(res)
    print(end-start)

    print('Try to get red inc when not on distro...')
    start = time.time()
    res = g4i.get_molecule(user_id=users1[2],
                           stix_ids=[inc_ids3[1]],
                           schema_name='incident',
                           objs=True,
                           pivot=False)
    end = time.time()
    pprint(res)
    print(end-start)

    print('Get remediations for an attack pattern...')
    start = time.time()
    res = g4i.get_molecule(user_id=users1[2],
                           stix_ids=["attack-pattern--4b74a1d4-b0e9-4ef1-93f1-14ecc6e2f5b5"],
                           schema_name='remediation',
                           objs=True,
                           pivot=False)
    end = time.time()
    pprint(res)
    print(end-start)

    print('Get MC-specific incident format...')
    start = time.time()
    res = g4i.get_incidents(user_id=users1[1],
                            focus='assigned')
    end = time.time()
    pprint(res)
    print(end-start)


if __name__ == '__main__':
    main()
