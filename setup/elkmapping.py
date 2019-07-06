import json

translator = {
    'integer': 'integer',
    'timestamp': 'date',
    'identifier': 'keyword',
    'string': 'text',
    'taxonomy': 'keyword',
}

taxonomies = [
    'labels',
    'relationship_type',
    'type',
    'id',
    'primary_motivation',
    'secondary_motivations',
    'resource_level',
    'sectors',
    'sophistication',
    'roles',
    'selectors',
]


class ElkMapping(object):

    def __init__(self, index_name, properties):
        self.index_name = index_name
        self.elk_mapping = {'mappings': {'properties': {}}}
        for prop in properties:
            if type(properties[prop]) is dict:
                # Treat as potentially nested...
                if len(properties[prop]) > 1:
                    self.elk_mapping['mappings']['properties'][prop] = {
                        'type': 'nested'
                    }
                    self.elk_mapping['mappings']['properties'][prop]['properties'] = {}
                    for sub_prop in properties[prop]:
                        if type(properties[prop][sub_prop]) is dict:
                            out_prop_type = translator[next(
                                iter(properties[prop][sub_prop]))]
                        else:
                            out_prop_type = translator[properties[prop][sub_prop]]
                        if sub_prop in taxonomies:
                            out_prop_type = translator['taxonomy']
                        self.elk_mapping['mappings']['properties'][prop]['properties'][sub_prop] = {
                            'type': out_prop_type
                        }
                    pass
                else:
                    self.elk_mapping['mappings']['properties'][prop] = {
                        'type': translator[next(iter(properties[prop]))]
                    }
            else:
                if prop in taxonomies:
                    out_prop_type = translator['taxonomy']
                else:
                    try:
                        out_prop_type = translator[properties[prop]]
                    except KeyError:
                        out_prop_type = properties[prop]
                self.elk_mapping['mappings']['properties'][prop] = {
                    'type': out_prop_type}

    def __repr__(self):
        return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))