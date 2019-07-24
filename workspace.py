import git4intel
from git4intel import TLPPlusMarking
import stix2
from datetime import datetime
import random
import uuid
from slugify import slugify
from pprint import pprint
import time


def get_deterministic_uuid(prefix=None, seed=None):
    if seed is None:
        stix_id = uuid.uuid4()
    else:
        random.seed(seed)
        a = "%32x" % random.getrandbits(128)
        rd = a[:12] + '4' + a[13:16] + 'a' + a[17:]
        stix_id = uuid.UUID(rd)

    return "{}{}".format(prefix, stix_id)


# def make_valid_commit(user_id):
#     ipv4 = stix2.v21.IPv4Address(value='8.8.8.8')
#     domain_name = stix2.v21.DomainName(
#         value='google.com')
#     obs_data = stix2.v21.ObservedData(first_observed=datetime.now(
#     ), last_observed=datetime.now(), number_observed=1, object_refs=[ipv4.id, domain_name.id], created_by_ref=user_id)
#     atp_hunter = stix2.v21.AttackPattern(
#         name="ATP Phase Definition from Hunter", created_by_ref=user_id)
#     ind_event = stix2.v21.Indicator(name="Collection of Observed Data signifying Event", labels=[
#                                     'malicious-activity'], pattern="[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019e']", pattern_type='stix', indicator_types=['malicious-activity'], created_by_ref=user_id)
#     rel_obsdata_ind = stix2.v21.Relationship(
#         source_ref=ind_event.id, target_ref=atp_hunter.id, relationship_type='indicates', created_by_ref=user_id)
#     rel_atp_mitre = stix2.v21.Relationship(
#         source_ref=atp_hunter.id, target_ref='attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add', relationship_type='relates_to', created_by_ref=user_id)
#     rel_ind_obsdata = stix2.v21.Relationship(
#         source_ref=ind_event.id, target_ref=obs_data.id, relationship_type='based_on', created_by_ref=user_id)

#     objs = [obs_data, domain_name, ipv4, atp_hunter, ind_event,
#             rel_atp_mitre, rel_obsdata_ind, rel_ind_obsdata]
#     grouping = stix2.v21.Grouping(
#         context='g4i commit', object_refs=objs, created_by_ref=user_id)

#     objs.append(grouping)

#     bundle = stix2.v21.Bundle(objs)
#     return bundle


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
                        relationship_type='located_at')
    bundle = stix2.v21.Bundle([user_id, loc_rel])
    return user_id, bundle


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
                        relationship_type='located_at')
    bundle = stix2.v21.Bundle([org_id, loc_rel])
    return org_id, bundle


def main():

    # Don't forget to download and install elasticsearch AND have it running
    #   before you run this...

    # Initialise client
    g4i = git4intel.Client('localhost:9200')

    # Setup the indices...
    # Use the stix2 version number specified - calls the current installed
    #   stix2 from running environment
    # print('Setting up indices...')
    # g4i.setup_es('21')

    # # Setup the core data (system idents, locations and default data markings)
    # # - hard coded config
    # print('Loading core data sets...')
    # print(g4i.store_core_data())

    # # Download latest Mitre Att&ck data from their taxii server as default
    # #   data set
    # # Ingest is a 'just get' policy for stix2, commit and molecule management
    # #    happen with background analytics to avoid ingestion slowness
    # print('Loading data primer (Mitre Att&ck)...')
    # print(g4i.data_primer())

    # Setup client user information - using the included dummy data for testing
    # print('Creating dummy user account...')
    user_id1, user_bundle1 = new_user('NEW UZ3R')
    print(g4i.register_ident(user_bundle1, 'individual'))

    print('Creating dummy organisation account...')
    org_id, org_bundle = new_org(user_id1.id)
    print(g4i.register_ident(org_bundle, 'organization'))

    print('Assigning created user to the created organisation...')
    org_rel1 = stix2.v21.Relationship(created_by_ref=user_id1.id,
                                      source_ref=user_id1,
                                      target_ref=org_id,
                                      relationship_type='relates_to')
    print(g4i.add_user_to_org(org_rel1))

    print('Create a second user account...')
    user_id2, user_bundle2 = new_user('Another NEW UZ3R')
    print(g4i.register_ident(user_bundle2, 'individual'))

    start = time.time()
    print('Invite second user to same organisation...')
    org_rel2 = stix2.v21.Relationship(created_by_ref=user_id2.id,
                                      source_ref=user_id2,
                                      target_ref=org_id,
                                      relationship_type='relates_to')
    print(g4i.add_user_to_org(org_rel2))

    # Indexing is much slower than search, so wait 1 second to catch up
    time.sleep(1)

    print('Check that the org information contains the new users...')
    print(user_id1.id, user_id2.id)
    pprint(g4i.get_org_info(org_id.id, user_id1.id))
    end = time.time()
    print(end - start)

    # # First step in exposure query below. Probably won't expose directly...
    # print('Show objects related to a stixid that also match a molecule...')
    # start = time.time()
    # res = g4i.get_molecule_rels(
    #             stixid='attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add',
    #             molecule=g4i.molecules['m_org'])
    # end = time.time()
    # pprint(res)
    # print(end-start)

    # q = {'query': {'bool': {'should': [{'bool': {'must': [{'match': {'target_ref': '6c018e7a-df51-40e8-9456-4531a423c5e7'}},
    #                                               {'match': {'relationship_type': 'relates_to'}},
    #                                               {'match': {'source_ref': 'identity'}}]}},
    #                            {'bool': {'must': [{'match': {'target_ref': 'identity'}},
    #                                               {'match': {'relationship_type': 'relates_to'}},
    #                                               {'match': {'source_ref': '6c018e7a-df51-40e8-9456-4531a423c5e7'}}]}},
    #                            {'bool': {'must': [{'match': {'target_ref': 'location'}},
    #                                               {'match': {'relationship_type': 'located_at'}},
    #                                               {'match': {'source_ref': '6c018e7a-df51-40e8-9456-4531a423c5e7'}}]}}]}}}
    # res = g4i.search(index='relationship',
    #                       body=q,
    #                       _source_includes=["source_ref", "target_ref"],
    #                       size=10000)
    # pprint(res)

if __name__ == "__main__":
    main()
