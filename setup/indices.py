import stix2
import sys
import inspect
import json
import collections
from pprint import pprint

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
        'tool_version': 'text'},
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
}

supported_types = [
    # '_STIXBase',
    'STIXDomainObject',
    'STIXRelationshipObject',
]

unsupported_props = [
    'ObservableProperty',
]


def update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def stixprop_to_field(prop_name, prop):
    is_object = False
    prop_type = type(prop).__name__
    try:
        es_type = schema_map[prop_type][prop_name]
    except KeyError:
        es_type = schema_defaults[prop_type]

    if es_type == 'nested' or es_type == 'object':
        out_dict = {prop_name: {'type': 'nested'}}
        for sub_prop in prop.contained._properties:
            update(out_dict, {prop_name: {'properties': stixprop_to_field(
                sub_prop, prop.contained._properties[sub_prop])[0]}})
        if es_type == 'object':
            is_object = True
        return out_dict, is_object
    else:
        return {prop_name: {'type': es_type}}, is_object


def stix_to_elk():
    for name, obj in inspect.getmembers(sys.modules[stix2.__name__]):
        if inspect.isclass(obj):
            class_type = inspect.getmro(obj)[1].__name__
            if class_type in supported_types:
                index_name = obj._type
                class_name = obj.__name__
                prop_list = getattr(
                    sys.modules[stix2.__name__], class_name)._properties
                mapping = {'mappings': {'properties': {}}}
                # print('---> ' + class_name)
                for prop in prop_list:
                    prop_type = type(prop_list[prop]).__name__
                    if prop_type not in unsupported_props:
                        es_prop = stixprop_to_field(prop, prop_list[prop])
                        if es_prop[1]:
                            update(mapping['mappings'], es_prop[0])
                        else:
                            update(mapping['mappings']
                                   ['properties'], es_prop[0])
                with open('./mappings/' + str(index_name) + '.json', 'w') as f:
                    json.dump(mapping, f, ensure_ascii=False, indent=4)


def main():
    stix_to_elk()


if __name__ == "__main__":
    main()
