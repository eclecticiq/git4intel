import json
import stix2
import sys
import collections
from datetime import datetime


def load_molecules(path):
    with open(path) as molecule_file:
        data = json.load(molecule_file)
    return data


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
    schema_map = {
        'ListProperty': {
            'external_references': 'nested',
            'goals': 'text',
            'granular_markings': 'nested',
            'kill_chain_phases': 'nested',
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
        'IDProperty': 'tokenized',
        'IntegerProperty': 'integer',
        'ListProperty': 'keyword',
        'MarkingProperty': 'object',
        'ObjectReferenceProperty': 'tokenized',
        'PatternProperty': 'text',
        'ReferenceProperty': 'tokenized',
        'StringProperty': 'keyword',
        'TimestampProperty': 'date',
        'TypeProperty': 'keyword',
        'BinaryProperty': 'binary',
        'ExtensionsProperty': 'object',
        'DictionaryProperty': 'object',
        'EmbeddedObjectProperty': 'object'
    }

    prop_type = type(prop).__name__

    try:
        es_type = schema_map[prop_type][prop_name]
    except KeyError:
        es_type = schema_defaults[prop_type]

    # Override anything ending in _ref or _refs with tokenized
    if prop_name[-5:] == '_refs' or prop_name[-4:] == '_ref':
        es_type = 'tokenized'

    if es_type == 'tokenized':
        return {prop_name: {'type': 'text', "analyzer": "stixid_analyzer"}}
    elif es_type == 'nested':
        out_dict = {prop_name: {'type': 'nested'}}
        for sub_prop in prop.contained._properties:
            update(out_dict, {prop_name: {'properties': stixprop_to_field(
                sub_prop, prop.contained._properties[sub_prop])}})
        return out_dict
    else:
        return {prop_name: {'type': es_type}}


def get_stix_ver_name(stix_ver):
    if stix_ver == '21':
        return stix2.v21.__name__
    else:
        return stix2.v20.__name__


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


def stix_to_elk(obj, stix_ver):
    unsupported_props = [
        'ObservableProperty',
    ]
    index_boilerplate = {
        "settings": {
            "analysis": {
                "analyzer": {
                    "stixid_analyzer": {
                        "tokenizer": "id_split"
                    }
                },
                "tokenizer": {
                    "id_split": {
                        "type": "pattern",
                        "pattern": "--"
                    }
                }
            }

        },
        'mappings': {'properties': {}}
    }
    class_name = obj.__name__
    prop_list = getattr(
        sys.modules[get_stix_ver_name(stix_ver)], class_name)._properties
    mapping = index_boilerplate
    for prop in prop_list:
        prop_type = type(prop_list[prop]).__name__
        if prop_type not in unsupported_props:
            update(mapping['mappings']['properties'], stixprop_to_field(
                prop, prop_list[prop]))
    return mapping


def todays_index(index_alias):
    return (index_alias + '-' + datetime.now().strftime("%y%m%d"))
