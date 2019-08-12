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
import time

from .utils import (
    compare_mappings,
    get_all_schemas,
    get_deterministic_uuid,
    get_locations,
    get_marking_definitions,
    get_os_licence,
    get_pii_marking,
    get_schema,
    get_stix_ver_name,
    get_system_id,
    get_system_org,
    get_system_to_org,
    md_time_index,
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
        self.pii_marking = get_pii_marking(self.identity['id'])[0]
        os_group_name = 'Open Source Data Markings'
        os_group_context = 'os-data-markings'
        self.os_group_id = get_deterministic_uuid(
                                      prefix='grouping--',
                                      seed=os_group_name + os_group_context)
        Elasticsearch.__init__(self, uri)

    # OVERLOADS
    def search(self, user_id, schema=None, _md=None, **kwargs):
        if _md is None:
            _md = True
        if 'index' not in kwargs:
            kwargs['index'] = 'intel'
        if 'size' not in kwargs:
            kwargs['size'] = 10000

        if not schema and not _md:
            return super().search(**kwargs)
        if _md:
            md_alias = self.get_id_markings(user_id=user_id, index_alias=kwargs['index'])
            kwargs['index'] = md_alias

        if schema:
            _schema_should = []
            if isinstance(schema, dict):
                _schema_should = [schema]
            else:
                if schema == 'all':
                    schemas = get_all_schemas()
                else:
                    if isinstance(schema, str):
                        schema = [schema]
                    schemas = []
                    for _schema in schema:
                        schemas.append(get_schema(_schema))
                for _schema in schemas:
                    _schema_should += _schema['bool']['should']

            _filter = {"bool": {"should": _schema_should}}
            kwargs['body'] = {"query": {"bool": {"must": kwargs['body']['query'],
                                                 "filter": _filter}}}
        return super().search(**kwargs)

    # SETS:
    def store_core_data(self):
        self.__setup_es(self.stix_ver)
        system_id = get_system_id()
        org_id = get_system_org(self.identity['id'])
        if not self.store_objects(system_id):
            print('Could not store system id.')
            return False
        if not self.store_objects(org_id):
            print('Could not store system org id.')
            return False

        org_rel = get_system_to_org(self.identity['id'], self.org['id'])
        if not self.store_objects(org_rel):
            print('Could not store system-org relationship.')
            return False

        markings, os_group_id = get_marking_definitions(self.identity['id'])
        self.os_group_id = os_group_id
        if not self.store_objects(markings):
            print('Could not store marking definitions.')
            return False

        locations = get_locations(self.identity['id'])
        if not self.store_objects(locations):
            print('Could not store locations.')
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
        md_json = json.loads(new_md.serialize())
        if not self.store_objects(md_json):
            return False

        return md_id, md_json

    def set_new_osdm(self, user_id, stix_id):
        os_group = self.get_object(user_id=user_id, obj_id=self.os_group_id)
        if stix_id in os_group['object_refs']:
            return True
        os_group['object_refs'].append(stix_id)

        res = self.__store_object(obj=os_group)
        return res

    # GETS:
    def get_id_markings(self, user_id, index_alias):
        # Get all marking definition refs that the identity is allowed
        #   to view. Assume that identities are allowed to view:
        # - objects with no marking references
        # - objects with _only_ os references (eg: TLP WHITE/GREEN)
        # - objects with a marking reference that explicitely includes their
        #   id in a distribution list (eg: tlp+)
        # - PII marked objects that are within their org chart
        md_alias_root, md_alias_date = md_time_index(user_id=user_id,
                                                     old_alias=index_alias)
        md_alias_name = md_alias_root + '--' + md_alias_date
        if self.indices.exists_alias(name=md_alias_name):
            return md_alias_name

        self.indices.delete_alias(index='_all',
                                  name=[md_alias_root + '*'],
                                  ignore=[400, 404])

        os_list = self.get_object(user_id=self.identity['id'],
                                  obj_id=self.os_group_id)['object_refs']
        valid_refs = [{"bool": {"must_not": {"exists": {
                                            "field": "object_marking_refs"}}}}]
        for os_id in os_list:
            valid_refs.append({"match": {
                                "object_marking_refs": os_id.split('--')[1]}})

        user_id_split = user_id.split('--')[1]

        # Get orgs that are in the user network from which they may inherit
        #   a distribution list ref (eg: marked TLP AMBER/RED for a whole org)
        q = {"query": {"bool": {"should": [
                                {"match": {"type": 'identity'}},
                                {"match": {"type": "relationship"}}]}}}
        org_objs = self.get_molecule(user_id=user_id,
                                     stix_ids=[user_id],
                                     schema_name='org',
                                     query=q,
                                     objs=True,
                                     _md=False)
        if not org_objs:
            return False
        org_should = [{"match": {
                        "definition.distribution_refs": user_id_split}}]
        for org in org_objs:
            org_id = org['id']
            if org['type'] == 'organization':
                org_should.append({"match": {"definition.distribution_refs":
                                   org_id.split('--')[1]}})
            valid_refs.append(
                {"bool": {"must": [
                    {"match": {"id": org_id.split('--')[1]}},
                    {"match": {"object_marking_refs":
                               self.pii_marking['id'].split('--')[1]}}
                ]}})
        q = {"query": {"bool": {"should": org_should}}}
        res = self.search(user_id=user_id,
                          index='marking-definition',
                          body=q,
                          filter_path=['hits.hits._source.id'],
                          _md=False)
        if res:
            for hit in res['hits']['hits']:
                valid_refs.append({"match": {"object_marking_refs":
                                  hit['_source']['id'].split('--')[1]}})
        body = {"filter": {"bool": {"should": valid_refs}}}
        alias_info = self.cat.aliases(name=index_alias, format='json')
        alias_mapping = []
        for info in alias_info:
            alias_mapping.append(info['index'])
        self.indices.put_alias(index=alias_mapping,
                               name=md_alias_name,
                               body=body)
        return md_alias_name

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
                                         schema_name=schema,
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
        if not docs:
            print('No docs found.')
            return False
        if len(docs) > 1:
            print('Multiple docs found (not handled atm).')
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

    def get_molecule(self, user_id, stix_ids, schema_name, objs=None,
                     query=None, pivot=None, _md=None):
        if _md is None:
            _md = True
        if pivot is None:
            pivot = True
        if not isinstance(schema_name, str):
            return False

        failed = 0
        ids = stix_ids[:]

        check_lst = []
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
            if pivot:
                schemas = [schema_name]
            else:
                schema_data = get_schema(schema_name)
                schemas = schema_data['bool']['should']
            count = 0
            for schema in schemas:
                if not pivot:
                    try:
                        if check_lst[count] is True:
                            continue
                    except IndexError:
                        pass
                res = self.search(user_id=user_id,
                                  body=q,
                                  schema=schema,
                                  _source_excludes=["created_by_ref", "object_marking_refs"],
                                  filter_path=['hits.hits._source.id',
                                               'hits.hits._source.*_ref',
                                               'hits.hits._source.*_refs'],
                                  _md=_md)
                if not pivot:
                    try:
                        check_lst[count] = bool(res)
                    except IndexError:
                        check_lst.append(bool(res))
                    count += 1
                if res:
                    for hit in res['hits']['hits']:
                        for value in list(hit['_source'].values()):
                            if isinstance(value, list):
                                for sub_value in value:
                                    if not sub_value:
                                        continue
                                    ids.append(sub_value)
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
                                  schema=schema_name,
                                  filter_path=['hits.hits._source'],
                                  _md=_md)
                output = []
                if res:
                    for hit in res['hits']['hits']:
                        output.append(hit['_source'])
                return output
            else:
                failed += 1
            if failed > 3:
                return False

    def get_incidents(self, user_id, focus=None):
        userid = user_id.split('--')[1]
        seeds = []
        print('Getting seed data...')
        start = time.time()
        if focus == 'assigned':
            q = {"query": {"bool":
                           {"must":
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
            q = {"query": {"bool":
                           {"must":
                            {"match": {"identity_class": 'organization'}}}}}
            org_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[user_id],
                                         schema_name='org',
                                         query=q,
                                         objs=True,
                                         pivot=True)
            if not org_objs:
                print('No organizations in org chart.')
                return False
            org_ids = []
            for org in org_objs:
                org_ids.append({"match": {"target_ref": org['id'].split('--')[1]}})

            q = {"query": {"bool": {"must": [
                                {"match": {"relationship_type": "targets"}},
                                {"bool": {"should": org_ids}}]}}}
            res = self.search(user_id=user_id, index='relationship', body=q,
                              filter_path=['hits.hits._source.source_ref'])
            if not res:
                print('No incidents targeting your organisation. '
                      'High five your neighbour.')
                return False

            for obj in res['hits']['hits']:
                seeds.append(obj['_source']['source_ref'])
        elif focus == 'my_sectors':
            q = {"query": {"bool": {"must": [{"match": {"identity_class": 'organization'}},
                                             {"exists": {"field": "sectors"}}]}}}
            org_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[user_id],
                                         schema_name='org',
                                         query=q,
                                         objs=True,
                                         pivot=True)
            if not org_objs:
                print('No organizations in org chart.')
                return False
            sectors = []
            for obj in org_objs:
                sectors += obj['sectors']
            if not sectors:
                print('No sectors defined on organizations.')
            sectors = list(set(sectors))
            print(sectors)
            q_sectors = []
            for sector in sectors:
                q_sectors.append({"match": {"sectors": sector}})
            q = {"query": {"bool": {"must": [
                            {"match": {"identity_class": 'organization'}},
                            {"bool": {"should": q_sectors}}]}}}
            # Use an _md False search just to get other org ids only.
            # Technically the org ids are PII, but this is a proportionate
            #   search that only returns ids of orgs with that sector.
            res = self.search(user_id=user_id, index='identity', body=q,
                              filter_path=['hits.hits._source.id'], _md=False)
            if not res:
                print('No incidents in defined sectors.')
                return False
            org_ids = []
            for hit in res['hits']['hits']:
                org_ids.append({"match": {"target_ref": hit['_source']['id'].split('--')[1]}})

            q = {"query": {"bool": {"must": [
                                {"match": {"relationship_type": "targets"}},
                                {"bool": {"should": org_ids}}]}}}
            # MDs reapplied here to ensure PII and other markings are respected
            res = self.search(user_id=user_id, index='relationship', body=q,
                              filter_path=['hits.hits._source.source_ref'])
            if not res:
                print('No incidents targeting your sector. '
                      'High five your neighbour.')
                return False

            for obj in res['hits']['hits']:
                seeds.append(obj['_source']['source_ref'])

            pprint(seeds)
        elif focus == 'my_ao':
            q = {"query": {"match": {"identity_class": 'organization'}}}
            org_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[user_id],
                                         schema_name='org_geo',
                                         query=q,
                                         objs=True)
            if not org_objs:
                print('No organizations in geo region.')
                return False
            org_ids = []
            for org in org_objs:
                org_ids.append({"match": {"target_ref": org['id'].split('--')[1]}})

            q = {"query": {"bool": {"must": [
                                {"match": {"relationship_type": "targets"}},
                                {"bool": {"should": org_ids}}]}}}
            res = self.search(user_id=user_id, index='relationship', body=q,
                              filter_path=['hits.hits._source.source_ref'])
            if not res:
                print('No incidents targeting your organisation. '
                      'High five your neighbour.')
                return False

            for obj in res['hits']['hits']:
                seeds.append(obj['_source']['source_ref'])
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
        end = time.time()
        print(end-start)

        output = []
        for seed in seeds:
            print('  ...inc get_molecule ' + seed)
            start = time.time()
            inc_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[seed],
                                         schema_name='incident',
                                         objs=True,
                                         pivot=False)
            end = time.time()
            print('  done: ' + str(end-start))
            if not inc_objs or len(inc_objs) < 2:
                continue
            inc = inc_objs[:]
            for inc_obj in inc_objs:
                try:
                    if inc_obj['relationship_type'] != 'phase-of':
                        continue
                    print('    ...phase get_molecule')
                    start = time.time()
                    phase_objs = self.get_molecule(user_id=user_id,
                                                   stix_ids=[inc_obj['source_ref']],
                                                   schema_name='phase',
                                                   objs=True,
                                                   pivot=False)
                    end = time.time()
                    print('    done: ' + str(end-start))
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
