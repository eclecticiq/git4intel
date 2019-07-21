import git4intel
import stix2
from datetime import datetime
import random
import uuid
from slugify import slugify
from pprint import pprint


def main():

    # Don't forget to download and install elasticsearch AND have it running before you run this...

    # Initialise client
    g4i = git4intel.Client('localhost:9200')
    # Show that there is a default identity for the core data set
    print(g4i.identity.id)

    # Setup the indices...
    # Use the stix2 version number specified - calls the current installed stix2 from running environment
    g4i.setup_es('21')

    # Setup the core data (locations and default data markings) - hard coded config
    responses = g4i.store_core_data()
    print(responses)

    # Download latest Mitre Att&ck data from their taxii server as default data set
    # Client automatically applies git4intel requirements on ingest (commit-style + default location/markings)
    # Should also trigger background analytic to identify molecules and create grouping objects for them - also for identities...just all of them...


    # Setup new hunting tool user identities/locations - maybe return similar ones based on identity molecules? generic get_molecule_rels function call


    # Basic get_molecule_rels call for an attack-pattern with no submitted data




    # print(g4i.identity.id)
    # markings = marking_definitions(g4i.identity.id)
    # print(markings)

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
