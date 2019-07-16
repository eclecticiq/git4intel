from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
import stix2
import json
import time
from pprint import pprint

with open('../config.json') as config_file:
    config = json.load(config_file)

with open('molecules.json') as molecule_file:
    molecules = json.load(molecule_file)


es = Elasticsearch(config['es_host'])

# Accept calls for Mitre Attack pattern id and keyword list
# Search on all entities known to relate to that id
# Search on all entities that contain those keywords (as phrases)
# Filter on marking definition as to what the user can see
# Post-filter to summarise results that they can't see

# Big improvement required here!!!
# Keyword searching currently just multi_matches against these fields
# Need to write a query creator that specifies fields depending on the type of keyword
# eg: if an ASN is sumnitted, split to RIR and number to query the autonomous-system index
# With the below current setting it should at least hit on IPs and Domains (using `value`)
keyword_query_fields = [
    "description",
    "name",
    "labels",
    "value",
]


def run_time_test():

    successful_query = {
        "query": {
            "nested": {
                "path": "kill_chain_phases",
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"kill_chain_phases.phase_name": "defense-evasion"}},
                            {"match": {"kill_chain_phases.kill_chain_name":  "mitre-attack"}}
                        ]
                    }
                },
                "inner_hits": {
                    "highlight": {
                        "fields": {
                            "kill_chain_phases.phase_name": {}
                        }
                    }
                }
            }
        }
    }

    test_results = {}
    test_runs = 10
    sum_times = 0.0
    for i in range(test_runs):
        ids = []
        start = time.time()
        res = es.search(index='intel', body=successful_query, size=1000)
        for hit in res['hits']['hits']:
            ids.append(hit['_source']['id'])
        end = time.time()
        # pprint(res)
        time_taken = end - start
        test_results[i] = time_taken
        sum_times += time_taken

    pprint(test_results)
    print('Average time taken: ' + str(sum_times / test_runs))


def all_type_ids(doc_type):
    q = {
        "query": {
            "match_all": {}
        },
        "stored_fields": []
    }
    res = es.search(index=doc_type, body=q, size=10000)
    for hit in res['hits']['hits']:
        print(doc_type + '--' + hit['_id'])


def print_rel_count(doc_type):
    q = {
        "query": {
            "match_all": {}
        },
        "stored_fields": []
    }
    res = es.search(index=doc_type, body=q, size=10000)
    rel_count = {}
    for hit in res['hits']['hits']:
        stixid = doc_type + '--' + hit['_id']
        rel_hits = get_atp_rels(stixid)
        rel_count[stixid] = int(rel_hits['hits']['total']['value'])

    sorted_relcount = sorted(rel_count.items(), key=lambda kv: kv[1])
    pprint(sorted_relcount)
    # attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add - Remote File Copy - 168 relationships to or from


def get_atp_rels(attack_id):
    q = {
        "_source": [
            "source_ref", "target_ref"
        ],
        "query": {
            "bool": {
                "should": [
                    {
                        "term": {"source_ref": attack_id}
                    },
                    {
                        "term": {"target_ref": attack_id}
                    }
                ]
            }
        }
    }

    res = es.search(index='relationship', body=q, size=10000)
    return res


def get_neighbours(stixid):
    res = get_atp_rels(stixid)
    orig_type = stixid.split('--')[0]
    neighbours = {
        'molecule_relevant': [],
        'suggestions': []
    }
    for hit in res['hits']['hits']:
        if hit['_source']['source_ref'] == stixid:
            related_id = hit['_source']['target_ref']
        else:
            related_id = hit['_source']['source_ref']
        id_parts = related_id.split('--')
        related_doctype = id_parts[0]
        related_docid = id_parts[1]

        # NOTE: Currently hard-coding for specific molecule config pattern. Need to figure out how to pass
        # specific molecule pattern to use OR whether we should just cycle them all...?
        if related_doctype in molecules['molecule_1'][orig_type]:
            res = es.get(index=related_doctype, id=related_docid)
            neighbours['molecule_relevant'].append(res['_source'])
        else:
            neighbours['suggestions'].append(related_id)

    return neighbours


def get_keyword_matches(keyword_list, neighbourhood=None):
    match_phrases = []
    # match_neighbours = []
    # if neighbourhood:
    #     for neighbour in neighbourhood:
    #         match_neighbours.append({"term": {"id": neighbour}})
    #     # print('Neighbour count: ' + str(len(match_neighbours)))
    for keyword in keyword_list:
        match_phrases.append({
            "multi_match": {
                "query": keyword,
                "type": "phrase",
                "fields": keyword_query_fields
            }
        })

        q = {
            "query": {
                "bool": {
                    "should": [{
                        "bool": {
                            "should": match_phrases,
                        },
                    }],
                    # "must": {
                    #     "bool": {
                    #         "should": match_neighbours
                    #     }
                    # }

                }
            }
        }

    res = es.search(index='sdo', body=q, size=10000)
    return res


def ea_query(attack_pattern_id, keyword_list):
    results = get_keyword_matches(keyword_list)
    results['neighbours'] = get_neighbours(attack_pattern_id)
    return results


def main():
    # res = get_neighbours(
    #     'attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add')
    # pprint(res)
    test_results = {}
    test_runs = 10
    sum_times = 0.0
    for i in range(test_runs):
        start = time.time()
        results = ea_query('attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add',
                           ["Sednit", "XTunnel"])
        end = time.time()
        time_taken = end - start
        test_results[i] = time_taken
        sum_times += time_taken

        # pprint(results)

        # for hit in results['hits']['hits']:
        #     print(hit['_source']['id'], hit['_score'])

    pprint(test_results)
    print('Average time taken: ' + str(sum_times / test_runs))


if __name__ == "__main__":
    main()
