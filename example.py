import git4intel
import stix2
from datetime import datetime


def marking_definitions():
    # Install basis marking definitions:
    # - TLP from stix API (except AMBER and RED which need to be extended for named recipient identity ids)
    # - PII for all idents and their relationships (including to locations) - required for user creation
    # - Default open source licence for any TLP WHITE/GREEN data

    tlp_white_dm = stix2.v21.common.TLP_WHITE
    tlp_green_dm = stix2.v21.common.TLP_GREEN
    os_licence = stix2.v21.common.OS_LICENSE
    pii_dm = stix2.v21.common.PII_DM

    objs = [tlp_green_dm, tlp_white_dm, pii_dm, os_licence]
    bundle = stix2.v21.Bundle(objs)
    return bundle


def countries():
    # Store static library on country-based location objects
    pass


def mitre_attack():

    # Don't forget to update_user() for Mitre Corporation on ingest!!!
    # Also, figure out how to submit appropriate groupings and use store_intel() api!!

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


def main():

    # Setup the indices...
    # g4i.setup_es('21')

    # Prime the database with data...
    datamarking_bundle = marking_definitions()

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
    #                     "source_ref.text": 'attack-pattern--',
    #                 },
    #                 "match": {
    #                     "target_ref.text": 'attack-pattern--',
    #                 },
    #             }],
    #         }
    #     }
    # }

    # res = git4intel.search(index='relationship', body=q, size=10000)
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
