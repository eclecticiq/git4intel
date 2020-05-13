# Git4Intelligence

Open standards on threat intelligence and knowledge management implemented in a best-of-breed way to enable deep provenance management and version control. Assertions tracked as object cluster/groupings in a way that provides real time access to relevant data to support actionable intelligence.

# Apologies up front...

This is very much a proof of concept library that was built to investigate the concept of behavioral models in intelligence data sets (molecules, in this instance) and to play with the ideas of git4intel. It's very rough and should not be used in production, but hopefully might be an interesting playground to test out ideas. The `workspace.py` script is a testbed script that I used to build examples and also build things on the fly, so is - in particular - a giant mess! I'll hopefully get around to cleaning it up a bit soon.

## Installation

Current build is designed to run off local setup of the code but should be able to handle remote elasticsearch host too.

* Make sure you have elasticsearch installed (tested up to 7.2, but no promises!)
* Copy/fetch this repo to local
* Install to a local env, so something like: `python3 -m pip install ./dist/git4intel-0.0.1.tar.gz`

## Usage
The git4intel client acts as a wrapper around the elasticsearch python client with specific function calls that ensure that searches are optimised and filters are applied appropriately.

* Make sure elasticsearch is running
* invoke the git4intel client and important setup functions to make the required changes to your specified elasticsearch instance as follows...
```g4i = git4intel.Client('localhost:9200')
g4i.store_core_data()
g4i.data_primer()
g4i.get_osquery('/Users/cobsec/git/osquery-attck')
g4i.get_sigma('/Users/cobsec/git/sigma/rules')```

Functions include:
* `store()` which takes a stix2 bundle and uses elasticsearch `index()` to push documents in to elasticsearch, applying necessary git4intel fields and 