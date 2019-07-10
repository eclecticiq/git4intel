#!/bin/bash

#Script to update stix2 module, then run indices.py to check if mappings have changed
#If mappings have changed, will spawn a new index with the revised mapping
echo "Running pip to update stix2..."

/usr/local/opt/python/bin/python3.7 -m pip install --upgrade stix2

echo "...complete! Running mapping setup to check for conflicts..."

/usr/local/opt/python/bin/python3.7 ./indices.py