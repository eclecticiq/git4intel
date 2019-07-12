

from stix2 import TAXIICollectionSource, Filter
from taxii2client import Collection
from pprint import pprint
import json
import sys
from elasticsearch import Elasticsearch

es = Elasticsearch()


def main():
    attack = {}

    collection = Collection(
        "https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e")

    tc_source = TAXIICollectionSource(collection)

    attack = tc_source.query()

    for obj in attack:
        try:
            res = es.index(
                index=obj['type'], id=obj['id'].split('--')[1], body=obj.serialize())
            print(res['result'])
        except AttributeError:
            print('---> NOT pushed: ' + obj['id'])


if __name__ == "__main__":
    main()
