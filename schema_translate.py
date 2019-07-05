import os
import json
from pprint import pprint

included_schemas = [
    'sdos',
    'sros',
]

# Sub properties for SROs which have horrible schemas...
sub_properties = [
    'allOf',
    'anyOf',
    'oneOf',
]

data_types = {
    'array'
}

def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


def extract_values(obj, key):
    """Pull all values of specified key from nested JSON."""
    arr = []

    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == key:
                    arr.append(v)
                elif isinstance(v, (dict, list)):
                    extract(v, arr, key)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    results = extract(obj, arr, key)
    return results


def property_to_mapping(prop_list):
    mappings = []
    for props in prop_list:
        for prop in props:

            if prop == 'id':
                mappings.append([prop, 'identifier'])
                break

            try:
                prop_type = props[prop]['type']

                if prop_type == 'array':
                    try:
                        # This will fail if it is a complex array...
                        out_prop_type = props[prop]['items']['type']
                        mappings.append([prop, 'nested'])
                    except KeyError:
                        refs = extract_values(props[prop]['items'], '$ref')
                        for ref in refs:
                            mappings.append([prop, resolve_ref(ref)])
                else:
                    out_prop_type = prop_type
                    mappings.append([prop, out_prop_type])
            except KeyError:
                # Handling properties that don't have a 'type' but might have a top-level '$ref'
                try:
                    prop_ref = props[prop]['$ref']
                    ref_props = resolve_ref(prop_ref)
                    mappings.append([prop, ref_props[0]])
                except KeyError:
                    # Handling properties that have neither 'type' nor top-level '$ref'
                    for field in props[prop]:
                        if field in sub_properties:
                            for elem in props[prop][field]:
                                try:
                                    ref_props = resolve_ref(elem['$ref'])
                                    mappings.append([prop, ref_props[0]])
                                except KeyError:
                                    pass
    return mappings


def resolve_ref(ref):
    filename = str(ref).split('/')[-1]
    abs_path = find(filename, '.')
    with open(abs_path) as json_data:
        data = json.load(json_data)
        try:
            if data['type'] == 'object':
                raise KeyError('Schema needs deep inspection...')
            mappings = [data['title'], data['type']]
        except KeyError:
            properties = extract_values(data, "properties")
            mappings = property_to_mapping(properties)
    return mappings


def map_simple_to_elk(simple_mappings):
    elk_mappings = {}
    for simple_mapping in simple_mappings:
        index_name = str(simple_mapping).split('/')[-1].split('.')[0]
        elk_mappings[index_name] = {
            "mappings": {
                "properties": {
                }
            }
        }
        # Might have to reorder this to get Nested vs Object mappings the right way around
        for field in simple_mappings[simple_mapping]:
            if field[0] == 'kill_chain_phases' or field[0] == 'granular_markings':
                elk_mappings[index_name]['mappings'][field[0]] = {
                    'properties': {
                    }
                }
                for sub_field in field[1]:
                    print field
                    elk_mappings[index_name]['mappings'][field[0]]['properties'][sub_field[0]] = sub_field[1]
            elif type(field[1]) is list:
                elk_mappings[index_name]['mappings']['properties'][field[0]] = {
                    'type': 'nested'
                }
            else:
                elk_mappings[index_name]['mappings']['properties'][field[0]] = {
                    'type': field[1]
                }
    return elk_mappings


def main():
    schema_field_list = {}
    # schema_dir = os.listdir('./schemas')
    schema_dir = included_schemas
    for directory in schema_dir:
        sub_dir = './schemas/' + directory
        for schema_file in os.listdir(sub_dir):
            filepath = sub_dir + '/' + schema_file
            with open(filepath) as json_data:
                data = json.load(json_data)
                properties = extract_values(data, "properties")
                mappings = property_to_mapping(properties)
                core_refs = resolve_ref("../common/core.json")
                for core_ref in core_refs:
                    mappings.append(core_ref)
                schema_field_list[data['id']] = mappings
    # pprint(schema_field_list)

    elk_mappings = map_simple_to_elk(schema_field_list)
    pprint(elk_mappings)


if __name__ == "__main__":
    main()
