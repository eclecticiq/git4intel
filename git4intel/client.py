from elasticsearch import Elasticsearch
import stix2
from taxii2client import Collection
import sys
import inspect
import re
import json
from stix2.v21 import CustomMarking
from stix2.properties import ListProperty, ReferenceProperty
from pprint import pprint

from .utils import (
    compare_mappings,
    get_deterministic_uuid,
    get_molecules,
    get_stix_ver_name,
    get_system_id,
    get_system_org,
    get_system_to_org,
    refresh_static_data,
    stix_to_elk,
    todays_index,
)


sdo_indices = [
    'attack-pattern',
    'campaign',
    'course-of-action',
    'grouping',
    'identity',
    'indicator',
    'infrastructure',
    'intrusion-set',
    'location',
    'malware',
    'malware-analysis',
    'note',
    'observed-data',
    'opinion',
    'report',
    'threat-actor',
    'tool',
    'vulnerability',
]


@CustomMarking('x-tlpplus-marking', [
    ('tlp_marking_def_ref', ReferenceProperty(
        type='marking-definition', required=True)),
    ('distribution_refs', ListProperty(
        ReferenceProperty(type='identity'), required=True))
])
class TLPPlusMarking(object):
    pass


class Client(Elasticsearch):

    def __init__(self, uri, molecule_file=None):
        self.stix_ver = '21'
        self.molecules = get_molecules(molecule_file)
        self.identity = get_system_id(id_only=True)
        self.org = get_system_org(system_id=self.identity['id'], org_only=True)
        Elasticsearch.__init__(self, uri)

    # SETS:
    def _store_obj(self, obj):
        id_parts = str(obj['id']).split('--')
        index_name = id_parts[0]
        doc_id = id_parts[1]
        res = self.index(index=index_name,
                         body=obj,
                         doc_type="_doc",
                         id=doc_id)
        if res['result'] == 'created' or res['result'] == 'updated':
            return True
        return False

    def store_intel(self, bundle, is_commit=None):
        if is_commit:
            if not self._check_commit(bundle):
                return False
        for stix_object in bundle['objects']:
            if not self._store_obj(stix_object):
                return False
        return True

    def store_core_data(self):
        self._setup_es(self.stix_ver)
        system_id_bundle = get_system_id()
        org_id_bundle = get_system_org(self.identity['id'])
        if not self.register_ident(system_id_bundle, 'system'):
            return False
        if not self.register_ident(org_id_bundle, 'organization'):
            return False

        org_rel = get_system_to_org(self.identity['id'], self.org['id'])
        if not self._store_obj(org_rel):
            return False

        static_data = refresh_static_data(self.identity['id'])
        if not self.store_intel(static_data):
            return False

        return True

    def register_ident(self, id_bundle, _type):
        # Must only contain a id obj and a location ref
        # _type must be the relevant class (org or individual)
        if len(id_bundle['objects']) != 2:
            return False

        for obj in id_bundle['objects']:
            obj_type = str(obj['id']).split('--')[0]
            if obj_type == 'identity' and obj['identity_class'] != _type:
                return False
            if obj_type == 'identity' or obj_type == 'relationship':
                if not self._store_obj(obj):
                    return False
        return True

    def add_user_to_org(self, org_rel):
        # Must only contain rel object for user_id to org_id
        org_id = org_rel['target_ref'].split('--')[1]
        ind_id = org_rel['source_ref'].split('--')[1]
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
        if not self._store_obj(org_rel):
            return False
        return True

    def set_tlpplus(self, user_id, tlp_marking_def_ref, distribution_refs):
        if user_id.split('--')[0] != 'identity':
            return False
        if not isinstance(distribution_refs, list):
            return False
        if (tlp_marking_def_ref != stix2.TLP_AMBER.id and
                tlp_marking_def_ref != stix2.TLP_RED.id):
            return False
        ref_list = distribution_refs[:]
        distribution_refs.append(tlp_marking_def_ref)
        distribution_refs = sorted(set(distribution_refs))
        md_id = get_deterministic_uuid(prefix='marking-definition--',
                                       seed=str(ref_list))
        if self.exists(index='marking-definition',
                       id=md_id.split('--')[1],
                       _source=False,
                       ignore=[400, 404]):
            return md_id
        tlp_plus = TLPPlusMarking(tlp_marking_def_ref=tlp_marking_def_ref,
                                  distribution_refs=ref_list)
        new_md = stix2.v21.MarkingDefinition(definition_type='tlp-plus',
                                             definition=tlp_plus,
                                             id=md_id,
                                             created_by_ref=user_id)
        if not self._store_obj(json.loads(new_md.serialize())):
            return False

        return md_id

    # CHECKS:
    def _check_commit(self, bundle):
        grouping_count = 0
        ids = []
        ident_ids = []
        group_obj_lst = []

        for obj in bundle['objects']:
            if obj['type'] == 'grouping':
                grouping_count += 1
                group_author = obj['created_by_ref']
                group_obj_lst = obj['object_refs']
            elif obj['type'] == 'identity':
                ident_ids.append(obj['id'])
                ids.append(obj['id'])
            else:
                try:
                    ids.append(obj['id'])
                except AttributeError:
                    pass

        if grouping_count == 1 and ids.sort() == group_obj_lst.sort():
            # Only 1 grouping and it refers to all objects in the commit - good
            if group_author in ident_ids:
                # Regardless of supplied identities, id of group author exists
                #   in kb - good
                return True
            elif self.exists(index='identity',
                             id=group_author.split('--')[1],
                             _source=False,
                             ignore=[400, 404]):
                # Explicit inclusion of id entity in commit - good
                return True
        # Otherwise, not enough info for commit - bad

        return False

    def _compare_bundle_to_molecule(self, bundle):
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

        for obj in bundle['objects']:
            if obj['type'] == 'relationship':
                source_type = obj['source_ref'].split('--')[0]
                target_type = obj['target_ref'].split('--')[0]
                rel_type = obj['relationship_type']
                for molecule in molecules:
                    try:
                        if (target_type in
                                molecules[molecule][source_type][rel_type]):
                            overall_score[molecule][0] += 1
                    except KeyError:
                        pass

        return overall_score

    # GETS:
    def _get_molecule_rels(self, stixid, molecule):
        obj_type = stixid.split('--')[0]
        obj_id = stixid.split('--')[1]
        q = {"query": {"bool": {"should": []}}}

        for from_type in molecule:
            for rel_type in molecule[from_type]:
                for to_type in molecule[from_type][rel_type]:
                    hits = 0
                    if from_type == obj_type:
                        source_field = obj_id
                        target_field = to_type
                        hits = 1
                    if to_type == obj_type:
                        source_field = from_type
                        target_field = obj_id
                        hits = 1
                    if to_type == from_type and to_type == obj_type:
                        hits = 2

                    for i in range(hits):
                        field_q = {"bool": {"must": [
                                    {"match": {"target_ref": target_field}},
                                    {"match": {"relationship_type": rel_type}},
                                    {"match": {"source_ref": source_field}}
                                ]}}
                        q['query']['bool']['should'].append(field_q)
                        # Swap fields in case second iteration (reverse rel)
                        target_field, source_field = source_field, target_field
        ids = []
        res = self.search(index='relationship',
                          body=q,
                          _source_includes=["source_ref", "target_ref"],
                          size=10000)
        for hit in res['hits']['hits']:
            if hit['_source']['source_ref'] != stixid:
                ids.append(hit['_source']['source_ref'])
            if hit['_source']['target_ref'] != stixid:
                ids.append(hit['_source']['target_ref'])

        return list(set(ids))

    def get_org_info(self, user_id, org_id):
        org_info = self._get_molecule_rels(stixid=org_id,
                                           molecule=self.molecules['m_org'])
        return self.get_objects(user_id=user_id, obj_ids=org_info)

    def get_countries(self):

        q = {
            "query": {
                "bool": {
                    "must": [{
                        "match": {
                            "created_by_ref": self.identity['id']
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

    def get_object(self, user_id, obj_id, values=None):
        if not isinstance(obj_id, str):
            return False
        docs = self.get_objects(user_id=user_id,
                                obj_ids=[obj_id],
                                values=values)
        if len(docs) > 1:
            return False
        return docs[0]

    def get_objects(self, user_id, obj_ids, values=None):
        # Get objects by stix_id ref (list of) and filtered by what I
        #   can see based on my user_id (id of individual identity object)
        #   ie: to include the org-walk of marking definitions in future
        # Currently does not apply filtering (based on marking definitions)
        # Also assumes that if you are referencing a specific id then it is
        #   because you got the id from something you can see, so org relevance
        #   filtering is not applicable (marking definition still is though!)
        if not obj_ids:
            return False
        if user_id.split('--')[0] != 'identity':
            return False

        docs = []
        if values:
            if not isinstance(values, list):
                return False
            q = {"query": {"bool": {"must": []}}}
            id_q = {"bool": {"should": []}}
            for obj_id in obj_ids:
                id_q["bool"]["should"].append(
                                    {"match":
                                        {"id": obj_id.split('--')[1]}})
            value_q = {"bool": {"should": []}}
            for value in values:
                value_q["bool"]["should"].append({"multi_match": {
                                                 "query": value}})

            q["query"]["bool"]["must"].append(value_q)
            q["query"]["bool"]["must"].append(id_q)
            res = self.search(index='intel',
                              body=q,
                              size=10000)
            for hit in res['hits']['hits']:
                docs.append(hit['_source'])
            return docs

        g = {"docs": []}
        for obj_id in obj_ids:
            g['docs'].append({"_index": obj_id.split('--')[0],
                              "_id": obj_id.split('--')[1]})

        res = self.mget(body=g)
        for doc in res['docs']:
            docs.append(doc['_source'])
        return docs

    def get_content(self, user_id, my_org_only=True, types=None, values=None,
                    expand_refs=True, group_contexts=None):
        # Get objects by type and/or value
        if user_id.split('--')[0] != 'identity':
            return False
        valid_authors = [user_id]
        user_info = self._get_molecule_rels(stixid=user_id,
                                            molecule=self.molecules['m_org'])
        if my_org_only:
            # Specify just objects created by you/your org/other org members
            for _id in user_info:
                obj_type = _id.split('--')[0]
                if obj_type != 'identity':
                    continue
                res = self.get_objects(user_id=user_id, obj_ids=[_id])
                if res[0]['identity_class'] != 'organization':
                    continue
                valid_authors.append(res[0]['id'])
                org_info = self._get_molecule_rels(
                                              stixid=res[0]['id'],
                                              molecule=self.molecules['m_org'])
                for other_user in org_info:
                    user_type = other_user.split('--')[0]
                    if user_type != 'identity':
                        continue
                    res = self.get_objects(user_id=user_id,
                                           obj_ids=[other_user])
                    if res[0]['identity_class'] != 'individual':
                        continue
                    valid_authors.append(res[0]['id'])
            valid_authors = list(set(valid_authors))
        else:
            # Future: same walk but get marking definitions as filter rather
            #   than created_by_ref, so 'everything I can see' rather than
            #   just what me/my org/other members created (but includes that)
            # That will probably be just the same search with author removed
            #   and rely on the future overloaded search function to filter
            pass

        q = {"query": {"bool": {"must": []}}}
        if my_org_only:
            auth_q = {"bool": {"should": []}}
            for author in valid_authors:
                auth_q["bool"]["should"].append(
                                {"match":
                                    {"created_by_ref": author.split('--')[1]}})
            q["query"]["bool"]["must"].append(auth_q)
        if types:
            type_q = {"bool": {"should": []}}
            for _type in types:
                if _type != 'grouping':
                    type_q["bool"]["should"].append({"match": {"type": _type}})
                    continue
                if group_contexts:
                    for context in group_contexts:
                        top_group = {"bool": {"must": []}}
                        top_group['bool']['must'].append({"match":
                                                         {"type": _type}})
                        top_group['bool']['must'].append({"match":
                                                         {"context": context}})
                        type_q['bool']['should'].append(top_group)
                    continue
                type_q["bool"]["should"].append({"match": {"type": _type}})

            q["query"]["bool"]["must"].append(type_q)
        res = self.search(index='intel',
                          body=q,
                          size=10000)
        child_ids = []
        parent_ids = []
        hit_ids = []
        results = []
        for hit in res['hits']['hits']:
            if hit['_source']['type'] == 'relationship':
                hit_ids.append(hit['_source']['id'])
                continue
            tmp_obj = {}
            for field in hit['_source']:
                child_ids = []
                if field == "created_by_ref":
                    continue
                if field[-4:] == '_ref':
                    child_ids = [hit['_source'][field]]
                    new_field = 'x_eiq_' + field + '_object'
                elif field[-5:] == '_refs':
                    child_ids = hit['_source'][field]
                    new_field = 'x_eiq_' + field + '_objects'
                if not child_ids:
                    continue
                parent_ids.append(hit['_source']['id'])

                child_objs = self.get_objects(user_id=user_id,
                                              obj_ids=child_ids,
                                              values=values)
                if child_objs:
                    tmp_obj[new_field] = []
                    for obj in child_objs:
                        tmp_obj[new_field].append(obj)
            if not tmp_obj:
                hit_ids.append(hit['_source']['id'])
                continue
            new_obj = {}
            new_obj.update(hit['_source'])
            new_obj.update(tmp_obj)
            results.append(new_obj)

        hit_ids = list(set(hit_ids))
        res = self.get_objects(user_id=user_id, obj_ids=hit_ids, values=values)
        if res:
            for hit in res:
                if hit['id'] not in child_ids:
                    results.append(hit)

        return results

    # SETUP:
    def _get_index_from_alias(self, index_alias):
        aliases = self.cat.aliases(name=[index_alias]).split(' ')
        for alias in aliases:
            if re.match(r'.+-[0-9]+', alias):
                return alias
        return False

    def _update_es_indexmapping(self, index_alias, new_mapping):
        new_index_name = todays_index(index_alias)

        if self.indices.exists(index=[new_index_name]):
            return False
        else:
            # Strip aliases from old index
            old_index_name = self._get_index_from_alias(index_alias)
            if old_index_name:
                self.indices.delete_alias(index=[old_index_name], name=[
                    index_alias, 'intel'])
            if index_alias in sdo_indices:
                self.indices.delete_alias(index=[old_index_name], name=['sdo'])

            self._new_index(index_alias, new_mapping)

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

    def _new_index(self, index_alias, mapping=None):
        index_name = todays_index(index_alias)
        self.indices.create(index=index_name, body=mapping)
        self.indices.put_alias(index=[index_name], name='intel')
        if index_alias in sdo_indices:
            self.indices.put_alias(index=[index_name], name='sdo')
        return self.indices.put_alias(index=[index_name], name=index_alias)

    def _setup_es(self, stix_ver):
        unsupported_types = [
            'archive-ext',
            'bundle',
            'http-request-ext',
            'icmp-ext',
            'language-content',
            'ntfs-ext',
            'pdf-ext',
            'raster-image-ext',
            'socket-ext',
            'statement',
            'tcp-ext',
            'tlp',
            'tlp-plus',
            'unix-account-ext',
            'windows-pebinary-ext',
            'windows-process-ext',
            'windows-registry-value-type',
            'windows-service-ext',
            'x509-v3-extensions-type'
        ]
        module_name = sys.modules[get_stix_ver_name(stix_ver)]
        for name, obj in inspect.getmembers(module_name):
            if not inspect.isclass(obj):
                continue
            try:
                index_name = obj._type
            except AttributeError:
                continue
            if index_name in unsupported_types:
                continue
            new_es_mapping = stix_to_elk(obj, stix_ver)
            tmp_mapping = self.indices.get_mapping(
                index=[index_name], ignore_unavailable=True)

            try:
                current_mapping = next(iter(tmp_mapping.values()))
                if not compare_mappings(current_mapping, new_es_mapping):
                    print(index_name + ' mapping is up to date!')
                    continue
                if not self._update_es_indexmapping(index_name,
                                                    new_es_mapping):
                    print(index_name +
                          ' was already updated today. Try again tomorrow.')
                    continue
                print('Index refreshed for ' + index_name)
            except StopIteration:
                resp = self._new_index(index_name, new_es_mapping)
                try:
                    if resp['acknowledged']:
                        print('Created new index for ' + index_name)
                except KeyError:
                    print('Failed to create new index for ' + index_name)

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
            try:
                doc = json.loads(obj.serialize())
            except AttributeError:
                doc = obj
            if not self._store_obj(doc):
                return False
        return True
