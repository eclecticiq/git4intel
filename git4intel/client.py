from elasticsearch import Elasticsearch
import stix2
import os
import sys
import inspect
import json
import re
from pprint import pprint

from .utils import (
    get_system_id,
    get_molecules,
    refresh_static_data,
    todays_index,
    compare_mappings,
    get_stix_ver_name,
    stix_to_elk
    )

sdo_indices = [
    'attack-pattern',
    'campaign',
    'course-of-action',
    'identity',
    'indicator',
    'intrusion-set',
    'malware',
    'observed-data',
    'report',
    'threat-actor',
    'tool',
    'vulnerability',
]


class Client(Elasticsearch):

    def __init__(self, uri, molecule_file=None):
        self.identity = get_system_id()
        self.molecules = get_molecules(molecule_file)
        Elasticsearch.__init__(self, uri)

    def store_obj(self, obj):
        id_parts = str(obj.id).split('--')
        index_name = id_parts[0]
        doc_id = id_parts[1]
        doc = obj.serialize()
        return super(Client, self).index(index=index_name, body=doc,
                                         doc_type="_doc", id=doc_id)

    def store_core_data(self):
        static_data = refresh_static_data(self.identity)
        responses = []
        for obj in static_data:
            res = self.store_obj(obj)
            responses.append(res)
        return responses

    def get_index_from_alias(self, index_alias):
        aliases = self.cat.aliases(name=[index_alias]).split(' ')
        for alias in aliases:
            if re.match(r'.+-[0-9]+', alias):
                return alias
        return False

    def update_es_indexmapping(self, index_alias, new_mapping):
        new_index_name = todays_index(index_alias)

        if self.indices.exists(index=[new_index_name]):
            return False
        else:
            # Strip aliases from old index
            old_index_name = self.get_index_from_alias(index_alias)
            if old_index_name:
                self.indices.delete_alias(index=[old_index_name], name=[
                    index_alias, 'intel'])
            if index_alias in sdo_indices:
                self.indices.delete_alias(index=[old_index_name], name=['sdo'])

            new_index(index_alias, new_mapping)

            # Reindexing requires at least 1 document in the index...
            if int(str(self.cat.count(index=[new_index_name])).split(' ')[2]) > 0:
                reindex_body = {
                    "source": {
                        "index": index_alias
                    },
                    "dest": {
                        "index": new_index_name
                    }
                }
                self.reindex(body=reindex_body)

            return True

    def new_index(self, index_alias, mapping):
        index_name = todays_index(index_alias)
        self.indices.create(index=index_name, body=mapping)
        # NOTE: support for tokenization not complete here, should be built in future, especially for relationship souce_ref and target_ref to support graph-like querying
        # tokenizer = get_tokenizer(index_name)
        # if tokenizer:
        #     self.indices.analyze(index=index_name, body=tokenizer['setup'])
        self.indices.put_alias(index=[index_name], name='intel')
        if index_alias in sdo_indices:
            self.indices.put_alias(index=[index_name], name='sdo')
        return self.indices.put_alias(index=[index_name], name=index_alias)

    def setup_es(self, stix_ver):
        supported_types = [
            # '_STIXBase',
            'STIXDomainObject',
            'STIXRelationshipObject',
            '_Observable',
            # '_Extension',
        ]
        # master_mapping = {}
        for name, obj in inspect.getmembers(sys.modules[get_stix_ver_name(stix_ver)]):
            if inspect.isclass(obj):
                class_type = inspect.getmro(obj)[1].__name__
                if class_type in supported_types:
                    index_name = obj._type
                    new_es_mapping = stix_to_elk(obj, stix_ver)
                    # update(master_mapping, new_es_mapping)

                    # index_name = 'intel'
                    # new_es_mapping = master_mapping
                    tmp_mapping = self.indices.get_mapping(
                        index=[index_name], ignore_unavailable=True)

                    try:
                        current_mapping = next(iter(tmp_mapping.values()))
                        if not compare_mappings(current_mapping, new_es_mapping):
                            print(index_name + ' mapping is up to date!')
                            pass
                        else:
                            if not self.update_es_indexmapping(index_name, new_es_mapping):
                                print(
                                    index_name + ' was already updated today. Try again tomorrow.')
                            else:
                                print('Index refreshed for ' + index_name)
                    except StopIteration:
                        resp = self.new_index(index_name, new_es_mapping)
                        try:
                            if resp['acknowledged'] == True:
                                print('Created new index for ' + index_name)
                        except KeyError:
                            print('Failed to create new index for ' + index_name)

    def check_commit(self, bundle):
        grouping_count = 0
        ids = []
        ident_ids = []
        group_obj_lst = []

        for obj in bundle.objects:
            if obj.type == 'grouping':
                grouping_count += 1
                group_author = obj.created_by_ref
                group_obj_lst = obj.object_refs
            elif obj.type == 'identity':
                ident_ids.append(obj.id)
                ids.append(obj.id)
            else:
                try:
                    ids.append(obj.id)
                except AttributeError:
                    pass

        if grouping_count == 1 and ids.sort() == group_obj_lst.sort():
            # Only 1 grouping and it refers to all objects in the commit - good
            if self.exists(index='intel', id=group_author, _source=False, ignore=[400, 404]):
                # Regardless of supplied identities, id of group author exists in kb - good
                return True
            elif group_author in ident_ids:
                # Explicit inclusion of id entity in commit - good
                return True
        # Otherwise, not enough info for commit - bad

        return False

    def store_intel(self, bundle):

        if check_commit(bundle):
            responses = []
            for stix_object in bundle.objects:
                response = store_obj(stix_object)
                responses.append(response)
        else:
            raise ValueError(
                'Bundle commit must have only 1 grouping object (where grouping.object_refs refers to every object other than grouping in the bundle) and where the grouping.created_by_ref refers to an ident already stored or in this commit.')
        return responses

    def get_rels(self, stixid):
        q = {
            "_source": [
                "source_ref", "target_ref"
            ],
            "query": {
                "bool": {
                    "should": [
                        {
                            "term": {"source_ref": stixid}
                        },
                        {
                            "term": {"target_ref": stixid}
                        }
                    ]
                }
            }
        }

        res = self.search(index='relationship', body=q, size=10000)
        return res

    def get_molecule_rels(self, stixid, molecule):
        res = self.get_rels(stixid)
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
        results['neighbours'] = self.get_molecule_rels(
            attack_pattern_id, molecule)
        return results

    # def update_user(self, bundle):
    #     # Assume correct org-suborg-individual and tooling structure is used to register a user
    #     # An end user can also be an automated system
    #     # Expect at least 1 related location to declare geographic interest
    #     # This function can be used to store a new user or update an existing one...maybe I should clean up old relationships too?
    #     # System should automatically data mark these entities as PII and otherwise there should be no marking references
    #     for obj in bundle.objects:
    #         if obj.type == 'relationship':
    #             source_type = obj.source_ref.split('--')[0]
    #             target_type = obj.target_ref.split('--')[0]
    #             if source_type != 'location' and source_type != 'identity':
    #                 return False
    #         elif obj.type == 'identity':
    #         elif obj.type == 'location':
    #         else:
    #             return False
    #     pass
