import os
import json
from pprint import pprint
from elkmapping import ElkMapping, ELKProperties

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
    mappings = {}
    for props in prop_list:
        for prop in props:
            if prop == 'external_references':
                pprint(props)
            if prop == 'id':
                mappings[prop] = 'identifier'
            else:
                try:
                    prop_type = props[prop]['type']

                    if prop_type == 'array':
                        try:
                            # This will fail if it is a complex array...
                            out_prop_type = props[prop]['items']['type']
                            mappings[prop] = out_prop_type
                        except KeyError:
                            refs = extract_values(props[prop]['items'], '$ref')
                            for ref in refs:
                                mappings[prop] = resolve_ref(ref)
                    else:
                        out_prop_type = prop_type
                        mappings[prop] = out_prop_type
                except KeyError:
                    # Handling properties that don't have a 'type' but might have a top-level '$ref'
                    try:
                        prop_ref = props[prop]['$ref']
                        ref_props = resolve_ref(prop_ref)
                        mappings[prop] = ref_props[0]
                    except KeyError:
                        # Handling properties that have neither 'type' nor top-level '$ref'
                        for field in props[prop]:
                            if field in sub_properties:
                                for elem in props[prop][field]:
                                    try:
                                        ref_props = resolve_ref(elem['$ref'])
                                        mappings[prop] = ref_props
                                    except KeyError:
                                        pass
    return mappings


def resolve_ref(ref):
    filename = str(ref).split('/')[-1]
    abs_path = find(filename, '.')
    mappings = {}
    with open(abs_path) as json_data:
        data = json.load(json_data)
        try:
            if data['type'] == 'object':
                raise KeyError('Schema needs deep inspection...')
            mappings[data['title']] = data['type']
        except KeyError:
            properties = extract_values(data, "properties")
            mappings = property_to_mapping(properties)
    return mappings


def main():
    # schema_dir = os.listdir('./schemas')
    schema_dir = included_schemas
    for directory in schema_dir:
        sub_dir = './schemas/' + directory
        for schema_file in os.listdir(sub_dir):
            # if schema_file == 'observed-data.json':
            #     break
            filepath = sub_dir + '/' + schema_file
            with open(filepath) as json_data:
                data = json.load(json_data)
                properties = extract_values(data, "properties")
                mappings = property_to_mapping(properties)
                core_refs = resolve_ref("../common/core.json")
                for core_ref in core_refs:
                    mappings[core_ref] = core_refs[core_ref]
                pprint(mappings)
                elk = ElkMapping(str(data['id']).split('/')[-1].split('.')[0], mappings)
                print(elk)
                with open('./mappings/' + str(elk.index_name) + '.json', 'w') as f:
                    json.dump(elk.elk_mapping, f, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    main()
