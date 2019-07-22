
# Background analytics
# Think I need a separate function call in Client that triggers these to run in the background...

def find_molecules():
    # Using the loaded molecule definitions, find matching objects and create a grouping object for them
    # Also consider creating a grouping object for partial matches that need more work ('draft' grouping?)
    pass

def find_commits():
    # Rummage through ingested data to identify specific commits (combination of author identity and author time)
    # Author time is challenging and probably needs a time window calculation (since objects can be 'created' and 'modified' programmatically which isn't always at exactly the same timestamp)
    pass

def upgrade_20_to_21():
    # Search for objects which are not stix 21 (eg: that don't have the mandated `spec_version` field) and create a new version with new authorship that is stx2
    pass