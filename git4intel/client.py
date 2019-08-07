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
    get_all_schemas,
    get_deterministic_uuid,
    get_schema,
    get_stix_ver_name,
    get_system_id,
    get_system_org,
    get_system_to_org,
    refresh_static_data,
    stix_to_elk,
    todays_index
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

    def __init__(self, uri):
        self.stix_ver = '21'
        self.identity = get_system_id(id_only=True)
        self.org = get_system_org(system_id=self.identity['id'], org_only=True)
        Elasticsearch.__init__(self, uri)

    # OVERLOADS
    def search(self, user_id, schema=None, **kwargs):
        if 'index' not in kwargs:
            kwargs['index'] = 'intel'
        if 'size' not in kwargs:
            kwargs['size'] = 10000

        _filter = None
        if schema:
            if schema == 'all':
                schemas = get_all_schemas()
            else:
                if isinstance(schema, str):
                    schema = [schema]
                schemas = []
                for _schema in schema:
                    schemas.append(get_schema(_schema))
            _filter_should = []
            for _schema in schemas:
                _filter_should += _schema['bool']['should']
            _filter = {"bool": {"should": _filter_should}}

        # Add to _filter for marking definitions (remove the _filter check)

        if _filter:
            kwargs['body'] = {"query": {"bool": {"must": kwargs['body']['query'],
                                                 "filter": _filter}}}
        return super().search(**kwargs)

    # SETS:
    def store_core_data(self):
        self.__setup_es(self.stix_ver)
        system_id = get_system_id()
        org_id = get_system_org(self.identity['id'])
        if not self.store_objects(system_id):
            return False
        if not self.store_objects(org_id):
            return False

        org_rel = get_system_to_org(self.identity['id'], self.org['id'])
        if not self.store_objects(org_rel):
            return False

        static_data = refresh_static_data(self.identity['id'])
        for obj in static_data:
            if not self.__store_object(obj):
                return False
        return True

    def __store_object(self, obj):
        id_parts = obj['id'].split('--')
        index_name = id_parts[0]
        doc_id = id_parts[1]
        res = self.index(index=index_name,
                         body=obj,
                         id=doc_id)
        if res['result'] == 'created' or res['result'] == 'updated':
            return True
        return False

    def store_objects(self, objects):
        if isinstance(objects, list):
            for obj in objects:
                if not self.__store_object(obj):
                    return False
            return True

        return self.__store_object(objects)

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
        if not self.store_objects(json.loads(new_md.serialize())):
            return False

        return md_id

    # GETS:
    def get_free_text(self, user_id, phrase, schema=None):
        output = []
        q = {"query": {"multi_match": {"query": phrase}}}
        res = self.search(user_id=user_id, body=q)
        if not res['hits']['hits']:
            return False
        if not schema:
            for hit in res['hits']['hits']:
                output.append(hit['_source'])
            return output

        for hit in res['hits']['hits']:
            hit_row = [hit['_source']]
            molecule = self.get_molecule(user_id=user_id,
                                         stix_ids=[hit['_source']['id']],
                                         schema=schema,
                                         objs=True)
            if molecule:
                hit_row.append(molecule)
            output.append(hit_row)
        return output

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
            res = self.search(user_id=user_id,
                              body=q)
            try:
                for hit in res['hits']['hits']:
                    docs.append(hit['_source'])
            except KeyError:
                return False
            return docs

        g = {"docs": []}
        for obj_id in obj_ids:
            g['docs'].append({"_index": obj_id.split('--')[0],
                              "_id": obj_id.split('--')[1]})

        res = self.mget(body=g)
        try:
            for doc in res['docs']:
                docs.append(doc['_source'])
        except KeyError:
            return False
        return docs

    def get_molecule(self, user_id, stix_ids, schema, objs=None, query=None):
        if not isinstance(schema, str):
            return False
        ids = stix_ids[:]
        while True:
            old_len = len(ids)
            q_ids = []
            q_str = ''
            for _id in ids:
                q_ids.append({"match": {"id": _id.split('--')[1]}})
                q_str += _id.split('--')[1] + " OR "
            q_str = q_str[:-4]

            q_ids.append({"query_string": {
                            "fields": ["*_ref", "*_refs"],
                            "query": q_str}})
            q = {"query": {"bool": {"must": {"bool": {"should": q_ids}}}}}
            res = self.search(user_id=user_id,
                              body=q,
                              schema=schema,
                              _source_excludes=["created_by_ref"],
                              filter_path=['hits.hits._source.id',
                                           'hits.hits._source.*_ref',
                                           'hits.hits._source.*_refs'])
            if not res:
                return False
            for hit in res['hits']['hits']:
                for value in list(hit['_source'].values()):
                    if isinstance(value, list):
                        ids += value
                        continue
                    ids.append(value)
            ids = list(set(ids))
            new_len = len(ids)
            if new_len == old_len:
                if not objs:
                    return ids
                q_objs = []
                for _id in ids:
                    q_objs.append({"match": {"id": _id.split('--')[1]}})
                if query:
                    q = {"query": {"bool": {"must": [
                                                query['query'],
                                                {"bool": {"should": q_objs}}
                                                ]}}}
                else:
                    q = {"query": {"bool": {"must": {"bool": {
                                                        "should": q_objs}}}}}
                res = self.search(user_id=user_id,
                                  body=q,
                                  schema=schema,
                                  filter_path=['hits.hits._source'])
                output = []
                for hit in res['hits']['hits']:
                    output.append(hit['_source'])
                return output

    def get_incidents(self, user_id, focus=None):
        userid = user_id.split('--')[1]
        seeds = []
        if focus == 'assigned':
            q = {"query": {"bool": {"must":
                                    {"match": {"x_eiq_assigned_to_ref": userid}}}}}
            res = self.search(user_id=user_id, index='attack-pattern', body=q,
                              schema='incident',
                              filter_path=['hits.hits._source.id'])
            if not res:
                print('No assigned incidents')
                return False
            for hit in res['hits']['hits']:
                seeds.append(hit['_source']['id'])
        elif focus == 'my_org':
            q = {"query": {"bool": {"must": {"match": {"identity_class": 'organization'}}}}}

            org_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[user_id],
                                         schema='org',
                                         query=q,
                                         objs=True)
            if not org_objs:
                print('No organizations in org chart.')
                return False
            for obj in org_objs:
                seeds.append(obj['id'])
        elif focus == 'my_sectors':
            q = {"query": {"bool": {"must": [{"match": {"identity_class": 'organization'}},
                                             {"exists": {"field": "sectors"}}]}}}
            org_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[user_id],
                                         schema='org',
                                         query=q,
                                         objs=True)
            if not org_objs:
                print('No organizations in org chart.')
                return False
            sectors = []
            for obj in org_objs:
                sectors += obj['sectors']
            if not sectors:
                print('No sectors defined on organizations.')
            sectors = list(set(sectors))
            q_sectors = []
            for sector in sectors:
                q_sectors.append({"match": {"sectors": sector}})
            q = {"query": {"bool": {"must": [
                            {"match": {"identity_class": 'organization'}},
                            {"bool": {"should": q_sectors}}]}}}
            res = self.search(user_id=user_id, index='identity', body=q,
                              filter_path=['hits.hits._source.id'])
            if not res:
                print('No incidents in defined sectors.')
                return False
            for hit in res['hits']['hits']:
                seeds.append(hit['_source']['id'])
        elif focus == 'my_ao':
            q = {"query": {"match": {"identity_class": 'organization'}}}
            org_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[user_id],
                                         schema='org_geo',
                                         query=q,
                                         objs=True)
            if not org_objs:
                print('No organizations in geo region.')
                return False
            for obj in org_objs:
                seeds.append(obj['id'])
        else:
            # Assume global
            q = {"query": {"exists": {"field": 'x_eiq_assigned_to_ref'}}}
            res = self.search(user_id=user_id, index='attack-pattern', body=q,
                              filter_path=['hits.hits._source.id'])
            if not res:
                print('No incidents assigned.')
                return False
            for hit in res['hits']['hits']:
                seeds.append(hit['_source']['id'])

        output = []
        for seed in seeds:
            inc_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[seed],
                                         schema='incident',
                                         objs=True)
            if not inc_objs or len(inc_objs) < 2:
                continue
            inc = inc_objs[:]
            for inc_obj in inc_objs:
                try:
                    if inc_obj['relationship_type'] != 'phase-of':
                        continue
                    phase_objs = self.get_molecule(user_id=user_id,
                                                   stix_ids=[inc_obj['source_ref']],
                                                   schema='phase',
                                                   objs=True)
                    inc.append(phase_objs)
                except KeyError:
                    pass
            output.append(inc)
        return output

    def get_countries(self):
        q = {"query": {"bool": {"must": [
                {"match": {"created_by_ref": self.identity['id']}}],
                "filter": [{"exists": {"field": "country"}}]}}}
        res = self.search(user_id=self.identity['id'],
                          index='location',
                          body=q,
                          _source=['name', 'id'])
        countries = {}
        for hit in res['hits']['hits']:
            countries[hit['_source']['id']] = hit['_source']['name']
        return countries

    # SETUP:
    def __get_index_from_alias(self, index_alias):
        aliases = self.cat.aliases(name=[index_alias]).split(' ')
        for alias in aliases:
            if re.match(r'.+-[0-9]+', alias):
                return alias
        return False

    def __update_es_indexmapping(self, index_alias, new_mapping):
        new_index_name = todays_index(index_alias)

        if self.indices.exists(index=[new_index_name]):
            return False
        else:
            # Strip aliases from old index
            old_index_name = self.__get_index_from_alias(index_alias)
            if old_index_name:
                self.indices.delete_alias(index=[old_index_name], name=[
                    index_alias, 'intel'])
            if index_alias in sdo_indices:
                self.indices.delete_alias(index=[old_index_name], name=['sdo'])

            self.__new_index(index_alias, new_mapping)

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

    def __new_index(self, index_alias, mapping=None):
        index_name = todays_index(index_alias)
        self.indices.create(index=index_name, body=mapping)
        self.indices.put_alias(index=[index_name], name='intel')
        if index_alias in sdo_indices:
            self.indices.put_alias(index=[index_name], name='sdo')
        return self.indices.put_alias(index=[index_name], name=index_alias)

    def __setup_es(self, stix_ver):
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
                if not self.__update_es_indexmapping(index_name,
                                                     new_es_mapping):
                    print(index_name +
                          ' was already updated today. Try again tomorrow.')
                    continue
                print('Index refreshed for ' + index_name)
            except StopIteration:
                resp = self.__new_index(index_name, new_es_mapping)
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
            if not self.store_objects(doc):
                return False
        return True
