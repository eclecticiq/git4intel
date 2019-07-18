# Git4Intelligence

Open standards on threat intelligence and knowledge management implemented in a best-of-breed way to enable deep provenance management and version control. Assertions tracked as object cluster/groupings in a way that provides real time access to relevant data to support actionable intelligence.

## Installation

Current build is designed to run off local setup of the code but should be able to handle remote elasticsearch host too.

* Copy/fetch this repo to local
* `python3 -m pip install ./dist/git4intel-0.0.1.tar.gz` to install
* Copy/fetch the patched version of cti-python-stix2 from [this branch](https://github.com/cobsec/cti-python-stix2)
* `python3 -m pip install ./dist/stix2eiq-0.0.1.tar.gz` to install the patched stix2 library which will behanve the same as stix2 (so `import stix2` and use as normal)
* Download and install [elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html) (and maybe kibana to track stuff), OR, if you already have an elasticsearch stack you want to use...

## Usage

* Make sure elasticsearch is running
* git4intel acts as a wrapper around the elasticsearch python client with specific function calls that ensure that searches are optimised and filters are applied appropriately (ie: ensuring the latest intel 'commits' are used, molecule pattern searching is optimised and client identities are used to filter what you are allowed to see...that last part isn't locked down just yet and will be handled later, this is just a PoC)

Functions include:
* `store()` which takes a stix2 bundle and uses elasticsearch `index()` to push documents in to elasticsearch, applying necessary git4intel fields and 


ToDo
* ~Setup IDE~
* ~Translate STIX2 json schemas in to a workable model, automated to keep up with schema changes~
* ~Use translation to create automated elasticsearch mappings for continuous deployment~
* ~Setup easy deployment to a local elk stack~
* ~Build some basic search harnesses to test it works~
* ~Import common libraries to elastic as stix2 literals (att&ck, galaxies, etc) - treated as a direct creator identity object (commit 1)~
* Ingest sample data feeds as literal stix2 (indcator feed, aptgo, other open source) - treated as an indirect interprative identity object (commit 1)
* Create interpolation layer to enhance feeds (ie: literal incoming --> data model) through _only adding_ stix entities (ie: no de-dupe, no deletion, no editing unless up-versioning because you can't because you aren't the creator) - treated as a direct creation from new identity object (commit 2)
* Create facility for adding further commits from other direct creation identity objects (commits x)
* Establish use cases for 'end goal' data 'molecules'
* Establish methods for moving from one to the other.

General Notes:
* Never delete or revoke entities unless the original source instructs to do so
* Need a `x_eiq_head` custom stix field on the 'latest' entities to be correlated to the complete (raw) landscape. This is _not_ the overall summarised threat picture as that differs from query to query
* When a user queries for intelligence, what they see is a summarised picture based on who they are and what they are querying for - by default run on all entities with `x_eiq_head == true`. Running on `false` would be for historic queries - more complex and requires tree walking to figure out if there are conflicts between maerges...but should be fine since deleting is no longer an issue (though have to decide whether referencing a 'replaced' entity is ok...or how that is represented in the translation layer).

Workflow:
* Hunter has done all of their stuff...ending in identifying a Mitre Att&ck attack-pattern as being relevant to their ongoing case/investigation/work
* Hunting platform creates a sighting entity and pushes that towards the ea_query api
* ea_query pushes the sighting in to the database
* ea_query searches on the id of the attack-pattern from the sighting object to return (all filtered by what the end user is allowed to see - otherwise ids only):  related entities (`molecule_relevant` all objects which fit the molecule pattern(s) (WHICH PATTERNS?!?), `suggestions` for all other related entities which the Hunter can verify with additional actions if applicable - TBC)