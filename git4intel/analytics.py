
# Background analytics
# Think I need a separate function call in Client that triggers these to run
#   in the background...


def find_molecules():
    # Identify sets of objects that partially fit the criteria for a molecule
    #   schema and return them to an endpoint for validation by an analyst
    pass


def upgrade_20_to_21():
    # Search for objects which are not stix 21 (eg: that don't have the
    #   mandated `spec_version` field / != 2.1) and create a new version with new
    #   authorship that is stix21
    pass
