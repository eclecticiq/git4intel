import json


def check_commit(bundle):
    grouping_count = 0
    identity_count = 0
    ids = []
    ident_ids = []
    group_obj_lst = []

    for obj in bundle.objects:
        if obj.type == 'grouping':
            grouping_count += 1
            group_author = obj.created_by_ref
            group_obj_lst = obj.object_refs
        elif obj.type == 'identity':
            identity_count += 1
            ident_ids.append(obj.id)
            ids.append(obj.id)
        else:
            try:
                ids.append(obj.id)
            except AttributeError:
                pass

    if grouping_count != 1 or identity_count < 1:
        return False
    else:
        if ids.sort() == group_obj_lst.sort():
            return True
        else:
            return False


def load_molecules(path):
    with open(path) as molecule_file:
        data = json.load(molecule_file)
    return data
