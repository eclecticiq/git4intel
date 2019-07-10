import stix2
import sys
import os
import inspect
import json
import collections
import requests
from pprint import pprint

from elasticsearch import Elasticsearch
from datetime import datetime

stix_ver = '20'

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


def update_es_indexmapping(index_alias, new_mapping):
    now = datetime.now()
    date_str = now.strftime("%y%m%d")
    new_index_name = index_alias + '-' + date_str

    es = Elasticsearch()
    if es.indices.exists(index=[new_index_name]):
        print('Wait until tomorrow to update...I guess...')
        return False

    es.indices.create(index=new_index_name, body=new_mapping)
    if es.indices.exists_alias([index_alias]):
        es.indices.delete_alias(index=[index_alias], name=[index_alias])
    es.indices.put_alias(index=[new_index_name], name=index_alias)

    return True


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
                # print(index_name)
                # pprint(new_es_mapping)
                cached_mapping_file = mapping_cache_dir + \
                    str(index_name) + '.json'

                try:
                    # get cached mapping
                    with open(cached_mapping_file) as json_file:
                        cached_mapping = json.load(json_file)

                    # compare and resave recache if needed
                    if ordered(new_es_mapping.items()) == ordered(cached_mapping.items()):
                        print(
                            "No updates in stix2 mapping from cache for " + index_name)
                    else:
                        raise FileNotFoundError(
                            "Update found and refreshed for " + index_name)
                except FileNotFoundError:
                    # cache for first time or recache data
                    update_detected = True
                    print("Caching " + index_name)
                    with open(cached_mapping_file, 'w') as f:
                        json.dump(new_es_mapping, f,
                                  ensure_ascii=False, indent=4)
    print(str(len(os.listdir(mapping_cache_dir))) + ' object mappings cached.')
    # pprint(master_mapping)
    if update_detected:
        with open('./' + stix_ver + 'master_mapping.json', 'w') as f:
            json.dump(master_mapping, f,
                      ensure_ascii=False, indent=4)
        print("Refreshed master mapping.")
        print(update_es_indexmapping('master', master_mapping))


if __name__ == "__main__":
    main()
