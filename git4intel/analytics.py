
# Background analytics
# Think I need a separate function call in Client that triggers these to run
#   in the background...


def upgrade_20_to_21():
    # Search for objects which are not stix 21 (eg: that don't have the
    #   mandated `spec_version` field / != 2.1) and create a new version with
    #   new authorship that is stix21
    pass


def resolve_upversions():
    # Identify up-versioned objects and suggest resolutions for non-breaking
    #   rollups of, for example, relationships that were on the old object that
    #   should be on the new one. (Think git merge).
    pass


def generic_to_specific():
    # Identify objects that are "generic" (such as an Identity that refers to
    #   an entire sector) and resolve them to specific objects (such as
    #   specific organisations) by applying correct molecule definition
    #   structures.
    pass


def create_assertions():
    # Find molecules that look similar to each other (more_like_this - with
    #   molecules) and recommend a new molecule that references the originals
    #   and represents them as 1 molecule. Need to think about how to handle
    #   the old molecules since they are unlikley to be authored by the
    #   searcher, so decide how to "replace" them with the new single version.
    #   Perhaps this is a good place to consider an extension to `revoked`? Or
    #   perhaps a filter for all molecules that doesn't just filter on revoked
    #   but also a mini-molecule of "is not derivative" )ie: does not have a
    #   relationship of type 'derived_from' pointing to it).
    pass
