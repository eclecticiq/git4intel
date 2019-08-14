.. _api:

API Documentation
=================

The g4i client uses the elasticsearch python API client and overloads certain methods to ensure the appropriate CTI functionality with the aim of exposing the power of elasticsearch and it's API without getting in the way. For that reason, the g4i API attempts to act as a pure wrapper for elasticsearch.py by overloading specific functions (such as ``search()``) to add stix/CTI relevant functionality without changing how you interact with the data itself.

However, stix (and arguably structured CTI in general) is inherently graph-like in structure so requires some knowledge of the schema and ability to create appropriate joins / parse the results for the intended purpose of the query. For that reason the client also provides a few core "join" functions (such as ``get_molecules()``) to leverage the scalability of elasticsearch whilst adhering to the inherent graph nature of stix v2.x. Whilst those functions may be useful endpoints to quickly get graph-like funcionality in to tooling, they will eventually become sub-optimal for larger datasets as they are performing multiple joins on the data in memory. Wherever possible it is better to do these joins at run time for the tool's specific data format which will allow you to query elasticsearch on a JIT basis.

The alternative would be to enforce some form of rigid data model that all users must adhere to in order to use the knowledge base - which goes against the philosophy of the project. Getting data in and querying it should be as open as elasticsearch itself. Getting it in to the format or adhering to the data model that the user or tool needs should be handled by the user/tool itself.

When you get comfortable with what the graph-like enpoints such as ``get_molecule()`` are doing, it is advised that you create your own queries using the core elasticsearch_ API.

.. _elasticsearch: https://elasticsearch-py.readthedocs.io/en/master/index.html


Git4Intel
---------

.. automodule:: git4intel.client
   :members: