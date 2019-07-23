from elasticsearch import Elasticsearch
import stix2
from taxii2client import Collection
import sys
import inspect
import re
from pprint import pprint
from stix2.v21 import CustomMarking
from stix2.properties import ListProperty, ReferenceProperty

from .utils import (
    get_system_id,
    get_molecules,
    refresh_static_data,
    todays_index,
    compare_mappings,
    get_stix_ver_name,
    stix_to_elk,
    get_external_refs,
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


@CustomMarking('x-tlpplus-marking', [
    ('tlp_marking_def_ref', ReferenceProperty(
        type='marking-definition', required=True)),
    ('distribution_refs', ListProperty(
        ReferenceProperty(type='identity'), required=True)),
])
class TLPPlusMarking(object):
    pass


class Client(Elasticsearch):

    def __init__(self, uri, molecule_file=None):
        self.identity = get_system_id()
        self.molecules = get_molecules(molecule_file)
        Elasticsearch.__init__(self, uri)

    def store_obj(self, obj):
        id_parts = str(obj['id']).split('--')
        index_name = id_parts[0]
        doc_id = id_parts[1]
        try:
            doc = obj.serialize()
        except AttributeError:
            doc = obj
        return super(Client, self).index(index=index_name, body=doc,
                                         doc_type="_doc", id=doc_id)

    def store_intel(self, bundle, is_commit=None):
        if is_commit:
            if not self.check_commit(bundle):
                raise ValueError(
                    'Bundle commit must have only 1 grouping object (where '
                    'grouping.object_refs refers to every object other than '
                    'grouping in the bundle) and where the '
                    'grouping.created_by_ref refers to an ident already stored'
                    ' or in this commit.')
        responses = []
        for stix_object in bundle.objects:
            response = self.store_obj(stix_object)
            responses.append(response)
        return responses

    def store_core_data(self):
        full_ids = get_system_id(full_org=True)
        static_data = refresh_static_data(self.identity.id)
        print(static_data)
        data_resp = self.store_intel(static_data)
        id_resp = self.register_user(full_ids)
        if id_resp:
            responses = id_resp + data_resp
            return responses
        else:
            raise ValueError(
                'Could not create system IDs. Check utils settings '
                'comply with check_user() conditions.')

    def data_primer(self):
        # Get Mitre Att&ck as a basis
        # Note: We don't apply commit control on ingest - it runs in the
        #   background so as not to slow down ingestion
        # If it's stix2.x - let it in.
        attack = {}
        collection = Collection(
            "https://cti-taxii.mitre.org/stix/collections/"
            "95ecc380-afe9-11e4-9b6c-751b66dd541e")
        tc_source = stix2.TAXIICollectionSource(collection)
        attack = tc_source.query()

        for obj in attack:
            res = self.store_obj(obj)
            print(str(res['result']) + ' ' + obj['id'])

    def register_ident(self, id_bundle, _type):
        # Must only contain a id obj and a location ref
        # _type must be the relevant class (org or individual)
        if len(id_bundle.objects) != 2:
            return False

        for obj in id_bundle.objects:
            obj_type = str(obj.id).split('--')[0]
            if obj_type == 'identity' and obj.identity_class != _type:
                return False
            if obj_type == 'identity' or obj_type == 'relationship':
                res = self.store_obj(obj)
                if res['result'] != 'created':
                    return False
        return True

    def add_user_to_org(self, org_rel):
        # Must only contain rel object for user_id to org_id
        org_id = org_rel.target_ref.split('--')[1]
        ind_id = org_rel.source_ref.split('--')[1]
        org_obj = self.get(index='identity',
                           id=org_id,
                           _source_includes='identity_class')
        if org_obj['_source']['identity_class'] != 'organization':
            return False
        ind_obj = self.get(index='identity',
                           id=ind_id,
                           _source_includes='identity_class')
        if ind_obj['_source']['identity_class'] != 'individual':
            return False
        return True

    def get_countries(self):

        q = {
            "query": {
                "bool": {
                    "must": [{
                        "match": {
                            "created_by_ref": self.identity.id
                        },
                    }],
                    "filter": [{
                        "exists": {
                            "field": "country"
                        },
                    }]
                }
            }
        }
        res = self.search(index='location', body=q, _source=[
                          'name', 'id'], size=10000)
        countries = {}
        for hit in res['hits']['hits']:
            countries[hit['_source']['id']] = hit['_source']['name']
        return countries

    def get_object(self, obj_id, user_id):
        # Get an object by stix_id ref (of the object) and filtered by what I 
        #   can see based on my user_id (id of individual identity object)
        # Currently does not apply filtering...
        if user_id.split('--')[0] != 'identity':
            return False

        res = self.get(index=obj_id.split(
            '--')[0], id=obj_id.split('--')[1], ignore=[400, 404])
        if res['found']:
            return res['_source']

        return False

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

            self.new_index(index_alias, new_mapping)

            # Reindexing requires at least 1 document in the index...
            num_indices = self.cat.count(index=[new_index_name])
            if int(str(num_indices).split(' ')[2]) > 0:
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

    def new_index(self, index_alias, mapping=None):
        index_name = todays_index(index_alias)
        self.indices.create(index=index_name, body=mapping)
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
        for name, obj in inspect.getmembers(sys.modules[
                                            get_stix_ver_name(stix_ver)]):
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
                        if not compare_mappings(current_mapping,
                                                new_es_mapping):
                            print(index_name + ' mapping is up to date!')
                            pass
                        else:
                            if not self.update_es_indexmapping(index_name,
                                                               new_es_mapping):
                                print(
                                    index_name + ' was already updated today. '
                                    'Try again tomorrow.')
                            else:
                                print('Index refreshed for ' + index_name)
                    except StopIteration:
                        resp = self.new_index(index_name, new_es_mapping)
                        try:
                            if resp['acknowledged']:
                                print('Created new index for ' + index_name)
                        except KeyError:
                            print('Failed to create new index for '
                                  + index_name)

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
            if group_author in ident_ids:
                # Regardless of supplied identities, id of group author exists
                #   in kb - good
                return True
            elif self.exists(
                             index='identity',
                             id=group_author.split('--')[1],
                             _source=False,
                             ignore=[400, 404]):
                # Explicit inclusion of id entity in commit - good
                return True
        # Otherwise, not enough info for commit - bad

        return False

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

    # def get_molecule_rels(self, stixid, molecule):

    #     q = {
    #         "query": {
    #             "bool": {
    #                 "must": [{
    #                     "match": {
    #                         "source_ref": 'identity',
    #                     },
    #                     "match": {
    #                         "target_ref": 'identity',
    #                     },
    #                 }],
    #             }
    #         }
    #     }

    #     res = self.get_rels(stixid)
    #     orig_type = stixid.split('--')[0]
    #     neighbours = {
    #         'molecule_relevant': [],
    #         'suggestions': []
    #     }
    #     for hit in res['hits']['hits']:
    #         if hit['_source']['source_ref'] == stixid:
    #             related_id = hit['_source']['target_ref']
    #         else:
    #             related_id = hit['_source']['source_ref']
    #         id_parts = related_id.split('--')
    #         related_doctype = id_parts[0]
    #         related_docid = id_parts[1]

    #         if related_doctype in self.molecules[molecule][orig_type]:
    #             res = self.get(index=related_doctype, id=related_docid)
    #             neighbours['molecule_relevant'].append(res['_source'])
    #         else:
    #             neighbours['suggestions'].append(related_id)

    #     return neighbours

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

    def get_molecule_rels(self, stixid, molecule):
        rel_types = {}
        # obj_id = stixid.split('--')[1]
        obj_type = stixid.split('--')[0]
        for from_type in molecule:
            print(from_type)
            if from_type == obj_type:
                get_all = True
            else:
                get_all = False
            for rel_type in molecule[from_type]:
                print(rel_type)
                for to_type in molecule[from_type][rel_type]:
                    print(obj_type, from_type, to_type, get_all)

                    if get_all:
                        print('here')
                        _match = {"source_ref": stixid}
                        _filter = {"target_ref": to_type}
                        q = {
                            "query": {
                                "bool": {
                                    "must": [{
                                        "match": _match,
                                    }],
                                    # "filter": [{
                                    #     "match": _filter,
                                    # }]
                                }
                            }
                        }
                        pprint(q)
                        res = self.search(
                            index='relationship', body=q, size=10000)
                        for hit in res['hits']['hits']:
                            print(hit['_source']['source_ref'],
                                  hit['_source']['target_ref'])
                        pprint(res)
                    elif to_type == obj_type:
                        _match = {"target_ref": stixid}
                        _filter = {"source_ref": from_type}
                        q = {
                            "query": {
                                "bool": {
                                    "must": [{
                                        "match": _match,
                                    }],
                                    # "filter": [{
                                    #     "match": _filter,
                                    # }]
                                }
                            }
                        }
                        pprint(q)
                        res = self.search(
                            index='relationship', body=q, size=10000)
                        for hit in res['hits']['hits']:
                            print(hit['_source']['source_ref'],
                                  hit['_source']['target_ref'])
                        pprint(res)

        return

    # def query_exposure(self, stixid, keyword_list, molecules=None):
    #     if not molecules:
    #         molecules = self.molecules

    #     for molecule in molecules:
    #         for obj_type in molecule:
    #             if stixid.split('--').[0] == obj_type:
    #                 rel_query = {"match": {"source_ref": stixid}
    #                 q = {
    #                     "query": {
    #                         "bool": {
    #                             "must": [{
    #                                 "match": {
    #                                     "source_ref": 'identity',
    #                                 },
    #                                 "match": {
    #                                     "target_ref": 'identity',
    #                                 },
    #                             }],
    #                         }
    #                     }
    #                 }
    #     pass

    def compare_bundle_to_molecule(self, bundle):
        molecules = self.molecules

        overall_score = {}
        for molecule in molecules:
            target_score = 0
            overall_score[molecule] = [0]
            for source in molecules[molecule]:
                for rel in molecules[molecule][source]:
                    target_score += len(
                        molecules[molecule][source][rel])
            overall_score[molecule].append(target_score)

        for obj in bundle.objects:
            if obj.type == 'relationship':
                source_type = obj.source_ref.split('--')[0]
                target_type = obj.target_ref.split('--')[0]
                rel_type = obj.relationship_type
                for molecule in molecules:
                    try:
                        if (target_type in
                                molecules[molecule][source_type][rel_type]):
                            overall_score[molecule][0] += 1
                    except KeyError:
                        pass

        return overall_score

    def check_user(self, bundle):
        # Assume correct org-suborg-individual and tooling structure is used to
        #   register a user
        # An end user can also be an automated system
        # Expect at least 1 related location to declare geographic interest
        # This function can be used to store a new user or update an existing
        #   one...maybe I should clean up old relationships too?
        # System should automatically data mark these entities as PII and
        #   otherwise there should be no marking references
        scores = self.compare_bundle_to_molecule(bundle)

        if scores['m_user'][1] > scores['m_user'][0]:
            return False

        extrefs = get_external_refs(bundle)
        for extref in extrefs:
            res = self.exists(index=extref.split('--')[0],
                              id=str(extref.split('--')[1]),
                              _source=False)
            return res
