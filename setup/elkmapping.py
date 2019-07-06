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
        self.elk_mapping = {'mapping': {'properties': {}}}
        for prop in properties:
            if type(properties[prop]) is dict:
                # Treat as potentially nested...
                if len(properties[prop]) > 1:
                    self.elk_mapping['mapping']['properties'][prop] = {
                        'type': 'nested'
                    }
                    self.elk_mapping['mapping']['properties'][prop]['properties'] = {}
                    for sub_prop in properties[prop]:
                        if type(properties[prop][sub_prop]) is dict:
                            out_prop_type = translator[next(
                                iter(properties[prop][sub_prop]))]
                        else:
                            out_prop_type = translator[properties[prop][sub_prop]]
                        if sub_prop in taxonomies:
                            out_prop_type = translator['taxonomy']
                        self.elk_mapping['mapping']['properties'][prop]['properties'][sub_prop] = {
                            'type': out_prop_type
                        }
                    pass
                else:
                    self.elk_mapping['mapping']['properties'][prop] = {
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
                self.elk_mapping['mapping']['properties'][prop] = {
                    'type': out_prop_type}

    def __repr__(self):
        return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))


class ELKProperties(object):
    def __init__(self, properties=None):
        allowed_types = [
            'text',
            'keyword',
            'long',
            'integer',
            'short',
            'byte',
            'double',
            'float',
            'date',
            'boolean',
            'binary',
        ]
        if type(properties) is list:
            self.properties = {}
            for prop in properties:
                if properties[prop] in allowed_types:
                    self.properties[prop] = properties[prop]
                else:
                    raise ValueError(
                        '--> Propery types must be allowed ELK datatypes')
        else:
            raise TypeError(
                '--> Must supply a dict of form "{<prop_name>: <prop_type>}')

    def __repr__(self):
        return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))


class ELKNest(object):

    # def set_attribute(object, attribute, input, _type, vocab_ref=None, required=False):
    #     if input is not None:
    #         if vocab_ref == 'datamarking':
    #             if is_datamarking(object, input):
    #                 setattr(object, attribute, input)
    #         elif is_valid(input, _type, vocab_ref):
    #             setattr(object, attribute, input)
    #     else:
    #         if required:
    #             err_required(object.type, attribute)

    # def labels(self, _labels):
    #     vocab_ref = self.type + '-label-ov'
    #     self.set_attribute('labels', _labels, list, vocab_ref, False)

    # def created(self, _created):
    #     self.set_attribute('created', _created, str, 'timestamp', True)

    # def modified(self, _modified):
    #     if self.type != 'marking-definition':
    #         self.set_attribute('modified', _modified, str, None, True)

    # def id(self, _id):
    #     self.set_attribute('id', _id, str, 'id', True)

    # def created_by_ref(self, _created_by_ref):
    #     self.set_attribute('created_by_ref', _created_by_ref, str, 'id', True)

    # def name(self, _name):
    #     required = True
    #     if self.type == 'relationship' or self.type == 'marking-definition':
    #         required = False
    #     self.set_attribute('name', _name, str, None, required)

    def __repr__(self):
        return json.dumps(self.__dict__, sort_keys=True, indent=4, separators=(',', ': '))
