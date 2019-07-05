# inc-mission-control-git4intel
Git4Intelligence

ToDo
* ~Setup IDE~
* ~Translate STIX2 json schemas in to a workable model, automated to keep up with schema changes~
* Use translation to create automated elasticsearch mappings for continuous deployment
* Import common libraries to elastic as stix2 literals (att&ck, galaxies, etc) - treated as a direct creator identity object (commit 1)
* Ingest sample data feeds as literal stix2 (indcator feed, aptgo, other open source) - treated as an indirect interprative identity object (commit 1)
* Create interpolation layer to enhance feeds (ie: literal incoming --> data model) through _only adding_ stix entities (ie: no de-dupe, no deletion, no editing unless up-versioning because you can't because you aren't the creator) - treated as a direct creation from new identity object (commit 2)
* Create facility for adding further commits from other direct creation identity objects (commits x)
* Establish use cases for 'end goal' data 'molecules'
* Establish methods for moving from one to the other.

General Notes:
* Never delete or revoke entities unless the original source instructs to do so
* Need a `x_eiq_head` custom stix field on the 'latest' entities to be correlated to the complete (raw) landscape. This is _not_ the overall summarised threat picture as that differs from query to query
* When a user queries for intelligence, what they see is a summarised picture based on who they are and what they are querying for - by default run on all entities with `x_eiq_head == true`. Running on `false` would be for historic queries - more complex and requires tree walking to figure out if there are conflicts between maerges...but should be fine since deleting is no longer an issue (though have to decide whether referencing a 'replaced' entity is ok...or how that is represented in the translation layer).

Testing some stuff...