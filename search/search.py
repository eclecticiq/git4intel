from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
import stix2
import json

es = Elasticsearch()


def attack_all():

    s = Search(using=es, index="intel") \
        .query("match_all")

    response = s.execute()

    # print(response)

    # count = 0
    objects = []
    for hit in s.scan():
        #     count += 1
        if hit.type != 'identity':
            objects.append(next(iter(hit.__dict__.values())))
        else:
            print('Got the id out!')
    # print(dir(hit))

    bundle = {
        "type": "bundle",
        "id": "bundle--b041e2e4-3648-4f8f-8975-b29386a489a8",
        "spec_version": "2.0",
        "objects": objects
    }
    # print(bundle)
    with open('data.json', 'w') as f:
        json.dump(bundle, f)

    # print(count)


def get_killchain_phase():
    s = Search(using=es, index="intel") \
        .query('match', phase_name='defense-evasion')

    response = s.execute()

    print(response)

    # count = 0
    # objects = []
    # for hit in s.scan():
    #     #     count += 1
    #     if hit.type != 'identity':
    #         objects.append(next(iter(hit.__dict__.values())))
    #     else:
    #         print('Got the id out!')
    # # print(dir(hit))

    # bundle = {
    #     "type": "bundle",
    #     "id": "bundle--b041e2e4-3648-4f8f-8975-b29386a489a8",
    #     "spec_version": "2.0",
    #     "objects": objects
    # }
    # # print(bundle)
    # with open('data.json', 'w') as f:
    #     json.dump(bundle, f)

    # print(count)


def main():
    get_killchain_phase()


if __name__ == "__main__":
    main()
