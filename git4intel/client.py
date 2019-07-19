from elasticsearch import Elasticsearch
import stix2

from .utils import *


class Client(Elasticsearch):

    def __init__(self, uri, molecule_data_path):
        self.molecules = load_molecules(molecule_data_path)
        Elasticsearch.__init__(self, uri)

    def store(self, bundle):
        if check_commit(bundle):
            responses = []
            for stix_object in bundle.objects:
                index_name = stix_object.type
                obj_id = str(stix_object.id).split('--')[1]
                tmp_obj = stix_object._inner
                response = super(Client, self).index(index=index_name, body=tmp_obj,
                                                     doc_type="_doc", id=obj_id)
                responses.append(response)
        else:
            raise ValueError(
                'Bundle commit must have only 1 grouping object (where grouping.object_refs refers to every object other than grouping in the bundle) and at least 1 identity object with `identity.id == grouping.created_by_ref`.')
        return responses

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

    def get_atp_rels(self, attack_id):
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

        res = self.search(index='relationship', body=q, size=10000)
        return res

    def get_neighbours(self, stixid, molecule):
        res = self.get_atp_rels(stixid)
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
            if related_doctype in self.molecules[molecule][orig_type]:
                res = self.get(index=related_doctype, id=related_docid)
                neighbours['molecule_relevant'].append(res['_source'])
            else:
                neighbours['suggestions'].append(related_id)

        return neighbours

    def query_related_phrases(self, keyword_list):
        keyword_query_fields = [
            "description",
            "name",
            "labels",
            "value",
        ]
        match_phrases = []
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
                    }
                }
            }

        res = self.search(index='sdo', body=q, size=10000)
        return res

    def query_exposure(self, attack_pattern_id, keyword_list, molecule=None):
        results = self.query_related_phrases(keyword_list)
        results['neighbours'] = self.get_neighbours(
            attack_pattern_id, molecule)
        return results
