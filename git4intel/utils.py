import json


def check_bundle_for_type(bundle, _type):
    for stix_object in bundle.objects:
        if stix_object.type == _type:
            return stix_object.id
    return False


def check_equal(lst):
    return not lst or lst.count(lst[0]) == len(lst)


def check_commit(bundle):
    sdos = [
        'attack-pattern',
        'campaign',
        'course-of-action',
        'indicator',
        'intrusion-set',
        'malware',
        'observed-data',
        'report',
        'threat-actor',
        'tool',
        'vulnerability',
    ]
    # Intel Commit Feature 1: identity object is present and applied as created_by_ref
    identity_id = check_bundle_for_type(bundle, 'identity')
    mod_ts = []
    if identity_id:
        for stix_object in bundle.objects:
            # mod_ts.append(stix_object.modified)
            if stix_object.type in sdos and stix_object.created_by_ref != identity_id:
                return False
    else:
        return False

    # Intel Commit Feature 2: modified timestamp must be the same for all objects§
    # if check_equal(mod_ts):
    #     return True
    # else:
    #     return False
    return True


def load_molecules(path):
    with open(path) as molecule_file:
        data = json.load(molecule_file)
    return data
