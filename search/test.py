from elasticsearch import Elasticsearch
# from elasticsearch_dsl import Search
import stix2
import json
from pprint import pprint
import time

es = Elasticsearch()


def main():
  # mapping = {
  #     "mappings": {
  #         "properties": {
  #             "user": {
  #                 "type": "nested"
  #             }
  #         }
  #     }
  # }
  # print(es.indices.create(index='my_index', body=mapping))

  # nested_docsdoc = {
  #     "group": "fans",
  #     "user": [
  #         {
  #             "first": "John",
  #             "last":  "Smith"
  #         },
  #         {
  #             "first": "Alice",
  #             "last":  "White"
  #         }
  #     ]
  # }

  # print(es.index(index='my_index', id='1', body=nested_docsdoc))

  failed_query = {
      "query": {
          "nested": {
              "path": "kill_chain_phases",
              "query": {
                  "bool": {
                      "must": [
                          {"match": {"kill_chain_phases.phase_name": "defense-evasion"}},
                          {"match": {"kill_chain_phases.kill_chain_name":  "lockheed-martin"}}
                      ]
                  }
              }
          }
      }
  }

  # print(es.search(index="intel", body=failed_query))

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
  test_runs = 1000
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

  # count = 0
  # for hit in res['hits']['hits']:
  #   count += 1
  #   pprint(hit['_source'])
  # print(count)

  # print('Search Execution Time: ' + str(end - start))


if __name__ == "__main__":
  main()
