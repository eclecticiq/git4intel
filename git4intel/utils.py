import json


def load_molecules(path):
    with open(path) as molecule_file:
        data = json.load(molecule_file)
    return data
