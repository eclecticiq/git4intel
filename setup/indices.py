import stix2
import sys
import os
import inspect
import json
import collections
import re
from pprint import pprint

from elasticsearch import Elasticsearch
from datetime import datetime

dir_path = os.path.dirname(os.path.realpath(__file__))
with open(dir_path + '/../config.json') as config_file:
    config = json.load(config_file)


def get_config(param):
    return config[param]


es = Elasticsearch(config['es_host'])
stix_ver = config['stix_ver']

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

schema_map = {
    'ListProperty': {
        'external_references': 'nested',
        'goals': 'text',
        'granular_markings': 'nested',
        'kill_chain_phases': 'nested'
    },
    'StringProperty': {
        'body': 'text',
        'contact_information': 'text',
        'data': 'text',
        'description': 'text',
        'name': 'text',
        'objective': 'text',
        'source_name': 'text',
        'statement': 'text',
        'tool_version': 'text',
        'administrative_area': 'text',
        'city': 'text',
        'street_address': 'text',
        'postal_code': 'text',
        'abstract': 'text',
        'authors': 'text'},
}

schema_defaults = {
    'BooleanProperty': 'boolean',
    'EnumProperty': 'keyword',
    'FloatProperty': 'float',
    'HashesProperty': 'keyword',
    'HexProperty': 'keyword',
    'IDProperty': 'keyword',
    'IntegerProperty': 'integer',
    'ListProperty': 'keyword',
    'MarkingProperty': 'object',
    'ObjectReferenceProperty': 'keyword',
    'PatternProperty': 'text',
    'ReferenceProperty': 'keyword',
    'StringProperty': 'keyword',
    'TimestampProperty': 'date',
    'TypeProperty': 'keyword',
    'BinaryProperty': 'binary',
    'ExtensionsProperty': 'object',
    'DictionaryProperty': 'object',
    'EmbeddedObjectProperty': 'object'
}

supported_types = [
    # '_STIXBase',
    'STIXDomainObject',
    'STIXRelationshipObject',
    '_Observable',
    # '_Extension',
]

unsupported_props = [
    'ObservableProperty',
]


def get_stix_ver_name():
    if stix_ver == '21':
        return stix2.v21.__name__
    else:
        return stix2.v20.__name__


def update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj


def stixprop_to_field(prop_name, prop):
    is_object = False
    prop_type = type(prop).__name__
    try:
        es_type = schema_map[prop_type][prop_name]
    except KeyError:
        es_type = schema_defaults[prop_type]

    if es_type == 'nested':
        out_dict = {prop_name: {'type': 'nested'}}
        for sub_prop in prop.contained._properties:
            update(out_dict, {prop_name: {'properties': stixprop_to_field(
                sub_prop, prop.contained._properties[sub_prop])}})
        return out_dict
    else:
        return {prop_name: {'type': es_type}}


def stix_to_elk(obj):
    class_name = obj.__name__
    prop_list = getattr(
        sys.modules[get_stix_ver_name()], class_name)._properties
    mapping = {'mappings': {'properties': {}}}
    for prop in prop_list:
        prop_type = type(prop_list[prop]).__name__
        if prop_type not in unsupported_props:
            update(mapping['mappings']['properties'], stixprop_to_field(
                prop, prop_list[prop]))
    return mapping


def todays_index(index_alias):
    return (index_alias + '-' + datetime.now().strftime("%y%m%d"))


def get_index_from_alias(index_alias):
    aliases = es.cat.aliases(name=[index_alias]).split(' ')
    for alias in aliases:
        if re.match(r'.+-[0-9]+', alias):
            return alias
    return False


def update_es_indexmapping(index_alias, new_mapping):
    new_index_name = todays_index(index_alias)

    if es.indices.exists(index=[new_index_name]):
        return False
    else:
        # Strip aliases from old index
        old_index_name = get_index_from_alias(index_alias)
        if old_index_name:
            es.indices.delete_alias(index=[old_index_name], name=[
                                    index_alias, 'intel'])
        if index_alias in sdo_indices:
            es.indices.delete_alias(index=[old_index_name], name=['sdo'])

        new_index(index_alias, new_mapping)

        # Reindexing requires at least 1 document in the index...
        if int(str(es.cat.count(index=[new_index_name])).split(' ')[2]) > 0:
            reindex_body = {
                "source": {
                    "index": index_alias
                },
                "dest": {
                    "index": new_index_name
                }
            }
            es.reindex(body=reindex_body)

        return True


def new_index(index_alias, mapping):
    index_name = todays_index(index_alias)
    es.indices.create(index=index_name, body=mapping)
    es.indices.put_alias(index=[index_name], name='intel')
    if index_alias in sdo_indices:
        es.indices.put_alias(index=[index_name], name='sdo')
    return es.indices.put_alias(index=[index_name], name=index_alias)


def compare_mappings(current_mapping, new_mapping):
    # Return True if there are differences
    # pprint(current_mapping)
    # pprint(new_mapping)
    for field in new_mapping['mappings']['properties']:
        try:
            if current_mapping['mappings']['properties'][field] != new_mapping['mappings']['properties'][field]:
                pprint(current_mapping['mappings']['properties'][field])
                pprint(new_mapping['mappings']['properties'][field])
                return True
        except KeyError:
            pprint(current_mapping['mappings']['properties'][field])
            pprint(new_mapping['mappings']['properties'][field])
            return True
    return False


def main():
    mapping_cache_dir = './' + stix_ver + 'mappings/'
    master_mapping = {}
    update_detected = False
    for name, obj in inspect.getmembers(sys.modules[get_stix_ver_name()]):
        if inspect.isclass(obj):
            class_type = inspect.getmro(obj)[1].__name__
            if class_type in supported_types:
                index_name = obj._type
                new_es_mapping = stix_to_elk(obj)
                update(master_mapping, new_es_mapping)

                # index_name = 'intel'
                # new_es_mapping = master_mapping
                tmp_mapping = es.indices.get_mapping(
                    index=[index_name], ignore_unavailable=True)

                try:
                    current_mapping = next(iter(tmp_mapping.values()))
                    if not compare_mappings(current_mapping, new_es_mapping):
                        print(index_name + ' mapping is up to date!')
                        pass
                    else:
                        if not update_index_mapping(index_name, new_es_mapping):
                            print(
                                index_name + ' was already updated today. Try again tomorrow.')
                        else:
                            print('Index refreshed for ' + index_name)
                except StopIteration:
                    resp = new_index(index_name, new_es_mapping)
                    try:
                        if resp['acknowledged'] == True:
                            print('Created new index for ' + index_name)
                    except KeyError:
                        print('Failed to create new index for ' + index_name)


if __name__ == "__main__":
    main()
