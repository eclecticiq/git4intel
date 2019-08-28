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


def main():

    # For the test, do a full index purge first...
    print(g4i.indices.delete(index=['_all']))

    # Lay out the core data and data primer...
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

    atp_id = "attack-pattern--6aac77c4-eaf2-4366-8c13-ce50ab951f38"
    iset_id = "intrusion-set--06a11b7e-2a36-47fe-8d3e-82c265df3258"

    # Do some targeting analysis...
    cam, cam_id = make_targeting(user_id=users1[1],
                                 campaign_name="CAMPAIGN",
                                 targeted_orgid=users1[0],
                                 atp_id=atp_id,
                                 iset_id=iset_id)

    # Do some attribution analysis...
    actor, actor_id = make_attribution(user_id=users1[1],
                                       actor_name="THREAT ACTOR",
                                       iset_id=iset_id)

    # Make org 2:
    org2, users2 = make_org(username1="User1",
                            username2="User2",
                            orgname="Arkham Ventures")
    # Event, phase and incident (red)
    red_inc1, inc_ids3 = make_incident(user_id=users2[1],
                                       target_org=users2[0],
                                       tlp='red',
                                       tlp_dist=[users1[1], users2[1]])

    objects = org1 + green_inc1 + green_inc2 + org2 + red_inc1 + cam + actor
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

    print('Get targeting of campaign...')
    start = time.time()
    res = g4i.get_molecule(user_id=users1[2],
                           stix_ids=[cam_id],
                           schema_name='targeting',
                           objs=True,
                           pivot=False)
    end = time.time()
    pprint(res)
    print(end-start)

    print('Get attribution of intrusion set...')
    start = time.time()
    res = g4i.get_molecule(user_id=users1[2],
                           stix_ids=[actor_id],
                           schema_name='attribution',
                           objs=True,
                           pivot=False)
    end = time.time()
    pprint(res)
    print(end-start)


if __name__ == '__main__':
    main()
