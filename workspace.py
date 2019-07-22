import git4intel
from git4intel import TLPPlusMarking
import stix2
from datetime import datetime
import random
import uuid
from slugify import slugify
from pprint import pprint

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
    ipv4 = stix2.v21.IPv4Address(value='8.8.8.8')
    domain_name = stix2.v21.DomainName(
        value='google.com')
    obs_data = stix2.v21.ObservedData(first_observed=datetime.now(
    ), last_observed=datetime.now(), number_observed=1, object_refs=[ipv4.id, domain_name.id], created_by_ref=user_id)
    atp_hunter = stix2.v21.AttackPattern(
        name="ATP Phase Definition from Hunter", created_by_ref=user_id)
    ind_event = stix2.v21.Indicator(name="Collection of Observed Data signifying Event", labels=[
                                    'malicious-activity'], pattern="[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019e']", pattern_type='stix', indicator_types=['malicious-activity'], created_by_ref=user_id)
    rel_obsdata_ind = stix2.v21.Relationship(
        source_ref=ind_event.id, target_ref=atp_hunter.id, relationship_type='indicates', created_by_ref=user_id)
    rel_atp_mitre = stix2.v21.Relationship(
        source_ref=atp_hunter.id, target_ref='attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add', relationship_type='relates_to', created_by_ref=user_id)
    rel_ind_obsdata = stix2.v21.Relationship(
        source_ref=ind_event.id, target_ref=obs_data.id, relationship_type='based_on', created_by_ref=user_id)

    objs = [obs_data, domain_name, ipv4, atp_hunter, ind_event,
            rel_atp_mitre, rel_obsdata_ind, rel_ind_obsdata]
    grouping = stix2.v21.Grouping(
        context='g4i commit', object_refs=objs, created_by_ref=user_id)

    objs.append(grouping)

    bundle = stix2.v21.Bundle(objs)
    return bundle

def create_user():
    # Feel free to add any details you like to the user/org, these are just the basics...
    new_username = 'NEW UZ3R'
    new_org_name = 'Acme Inc'
    org_loc_id = "location--9461b739-9f70-4c7c-a344-529c487ab4db"
    user_id = stix2.v21.Identity(id=get_deterministic_uuid(prefix="identity--", seed=new_username), identity_class='individual', name=new_username, sectors=[slugify("IT Consulting & Other Services")])
    org_id = stix2.v21.Identity(id=get_deterministic_uuid(prefix="identity--", seed=new_org_name), identity_class='organization', name=new_org_name, sectors=[slugify("IT Consulting & Other Services")])
    org_rel = stix2.v21.Relationship(id=get_deterministic_uuid(prefix="relationship--", seed=(str(user_id.id) + str(org_id.id) + 'relates_to')), source_ref=user_id.id, target_ref=org_id.id, relationship_type='relates_to')
    loc_rel = stix2.v21.Relationship(id=get_deterministic_uuid(prefix="relationship--", seed=(str(org_id.id) + org_loc_id + 'located_at')), source_ref=org_id.id, target_ref=org_loc_id, relationship_type='located_at')
    bundle = stix2.v21.Bundle([user_id, org_id, org_rel, loc_rel])
    return user_id, bundle

def main():

    # Don't forget to download and install elasticsearch AND have it running before you run this...

    # Initialise client
    g4i = git4intel.Client('localhost:9200')
    # Show that there is a default identity for the core data set
    print(g4i.identity.id)

    # Setup the indices...
    # Use the stix2 version number specified - calls the current installed stix2 from running environment
    g4i.setup_es('21')

    # # Setup the core data (locations and default data markings) - hard coded config
    core_responses = g4i.store_core_data()

    # Download latest Mitre Att&ck data from their taxii server as default data set
    # Ingest is a 'just get' policy for stix2, commit and molecule management happen with background analytics to avoid ingestion slowness
    g4i.data_primer()

    # Setup new hunting tool user identities/locations...
    # User will need to specify a country so we can relate to it with an idref - so use this function to get a list from the backend...
    countries = g4i.get_countries()
    # ...obviously I've hard coded it in this example (in `create_user()`, but you get the idea...
    # Have a function at _your_ end that can generate the user data. The below referenced `create_user()` is just an example
    user_id, id_bundle = create_user()
    # Register the user:
    responses = g4i.register_user(id_bundle)

    # Have a function at _your_ end that can generate a valid commit. The below referenced `make_valid_commit()` is just an example
    hunt_bundle = make_valid_commit(user_id)
    # Then store it in g4i. This one _is_ a commit so needs to have `is_commit` set to True for validation checks
    store_intel_responses = g4i.store_intel(bundle=hunt_bundle, is_commit=True)



    # Basic get_molecule_rels call for an attack-pattern with no submitted data

    # keyword_query_fields = [
    #     "source_ref",
    #     "target_ref",
    # ]
    # match_phrases = [{
    #     "multi_match": {
    #         "query": '.*attack-pattern--.*',
    #         "type": "phrase",
    #         "fields": keyword_query_fields
    #     }
    # }]

    # q = {
    #     "query": {
    #         "bool": {
    #             "should": [{
    #                 "match": {
    #                     "source_ref": 'identity',
    #                 },
    #                 "match": {
    #                     "target_ref": 'identity',
    #                 },
    #             }],
    #         }
    #     }
    # }

    # res = g4i.search(index='relationship', body=q, size=10000)
    # pprint(res)

    # bundle = make_some_stix()

    # # Push a bundle in to git4intel - returns a list of responses, 1 for each object
    # res = git4intel.store_intel(bundle)
    # print(res)

    # # Provide a stix id and a list of keywords - returns a scored list of related objects (es), a list of related entities
    # res = git4intel.query_exposure('attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add',
    #                                ["Sednit", "XTunnel"], 'm_hunt')
    # print(res)


if __name__ == "__main__":
    main()
