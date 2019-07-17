from stix2 import TAXIICollectionSource, Filter
from taxii2client import Collection
from pprint import pprint
import json
import sys
from elasticsearch import Elasticsearch
import os

dir_path = os.path.dirname(os.path.realpath(__file__))
with open(dir_path + '/../config.json') as config_file:
    config = json.load(config_file)


def get_config(param):
    return config[param]


es = Elasticsearch(config['es_host'])


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
            print(str(res['result']) + ' ' + obj['id'])
        except AttributeError:
            print('---> NOT pushed (serialization issues): ' + obj['id'])


if __name__ == "__main__":
    main()
