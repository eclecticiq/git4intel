"""A python class to turn elasticsearch into a CTI repository.

Attributes:
    sdo_indices (:obj:`list` of :obj:`str`): Global list of actively supported
        STIX Domain Objects (SDOs) that each have it's own elasticsearch index.
"""
from elasticsearch import Elasticsearch, exceptions
import stix2
from taxii2client import Collection
import sys
import inspect
import re
import json
from stix2.v21 import CustomMarking
from stix2.properties import ListProperty, ReferenceProperty
from pprint import pprint
import time

from .utils import (
    compare_mappings,
    get_all_schemas,
    get_deterministic_uuid,
    get_locations,
    get_marking_definitions,
    get_pii_marking,
    get_schema,
    get_stix_ver_name,
    get_system_id,
    get_system_org,
    get_system_to_org,
    md_time_index,
    new_obj_version,
    stix_to_elk,
    todays_index
)


sdo_indices = [
    'attack-pattern',
    'campaign',
    'course-of-action',
    'grouping',
    'identity',
    'indicator',
    'infrastructure',
    'intrusion-set',
    'location',
    'malware',
    'malware-analysis',
    'note',
    'observed-data',
    'opinion',
    'report',
    'threat-actor',
    'tool',
    'vulnerability',
]


@CustomMarking('x-tlpplus-marking', [
    ('tlp_marking_def_ref', ReferenceProperty(
        type='marking-definition', required=True)),
    ('distribution_refs', ListProperty(
        ReferenceProperty(type='identity'), required=True))
])
class TLPPlusMarking(object):
    pass


class Client(Elasticsearch):
    """Wrapper for the elasticsearch python client.

    Sets up some core attributes for setitng up the CTI repository:

    - identity (:obj:`dict`): Identity stix2 object for the system identity
      in order to setup core data.
    - org (:obj:`dict`): Identity stix2 object for the system's organisation
      identity in order to setup core data.
    - os_group_id (:obj:`str`): STIX2 grouping object reference id for marking
      definitions that allow all users of the repository to see that
      referenced object (eg: TLP WHITE).
    - pii_marking (:obj:`dict`): Marking-definition stix2 object that is to
      be applied to all objects considered Personally Identifiable
      Information.
    - stix_ver (:obj:`str`): Currently hard-coded (but provided for
      anticipation of future requirement) stix version number for the
      repository.

    Args:
        uri (:obj:`str`): Endpoint for elasticsearch.
    """

    def __init__(self, uri):
        self.stix_ver = '21'
        self.identity = get_system_id(id_only=True)
        self.org = get_system_org(system_id=self.identity['id'], org_only=True)
        self.pii_marking = get_pii_marking(self.identity['id'])[0]
        Elasticsearch.__init__(self, uri)
        try:
            res = self.search(user_id=self.identity['id'],
                              index='grouping',
                              body={"query": {"match": {"context":
                                                        "os-data-markings"}}},
                              _md=False)
        except exceptions.NotFoundError:
            os_group_name = 'Open Source Data Markings'
            os_group_context = 'os-data-markings'
            seed = os_group_name + os_group_context
            self.os_group_id = get_deterministic_uuid(prefix='grouping--',
                                                      seed=seed)
            return

        if len(res['hits']['hits']) < 1:
            os_group_name = 'Open Source Data Markings'
            os_group_context = 'os-data-markings'
            seed = os_group_name + os_group_context
            self.os_group_id = get_deterministic_uuid(prefix='grouping--',
                                                      seed=seed)
        elif len(res['hits']['hits']) == 1:
            self.os_group_id = res['hits']['hits'][0]['_source']['id']
        else:
            raise ValueError("Multiple active OS marking groups detected.")

    def search(self, user_id, schema=None, _md=None, revoked=None, **kwargs):
        """Wrapper for the elasticsearch ``search()`` method.

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            schema (:obj:`str` name or :obj:`dict` object, optional):
                Elasticsearch query to represent the 'molecule' of stix2
                objects as a filter to include objects that represent an
                intelligence category (eg: incident data as a cluster of stix
                objects).
            _md (:obj:`bool`, optional): Defaults to ``True`` to ensure that
                users are only able to see data in the results that they are
                allowed to as per stix2 marking definitions (md). Should only
                be set to ``False`` for zero-knowledge searches with
                appropriate anonymisation (eg: user searching for organisation
                members requires a join on the organisations they are a member
                of first before they can find out if they are allowed to see
                the data).
            revoked (:obj:`bool`, optional): Defaults to ``False`` to limit
                responses to only objects that are currently valid (ie: not
                revoked); Set to ``True`` to include revoked objects in the
                search.
            **kwargs: As per elasticsearch ``search()`` arguments.

        Returns:
            :obj:`dict`: JSON serializable dictionary per
            ``elasticsearch.search()``.
        """
        _filter = {}
        if _md is None:
            _md = True
        if revoked is None:
            revoked = False
        if 'index' not in kwargs:
            kwargs['index'] = 'intel'
        if 'size' not in kwargs:
            kwargs['size'] = 10000

        # if not schema and not _md:
        #     return super().search(**kwargs)
        if _md:
            md_alias = self.get_id_markings(user_id=user_id,
                                            index_alias=kwargs['index'])
            kwargs['index'] = md_alias

        if not revoked:
            _filter = {"bool": {"should": [
                                    {"bool": {"must_not": {"exists": {
                                        "field": "revoked"}}}},
                                    {"bool": {"must_not": {"match": {
                                        "revoked": True}}}}]}}

        if schema:
            _schema_should = []
            if isinstance(schema, dict):
                _schema_should = [schema]
            else:
                if schema == 'all':
                    schemas = get_all_schemas()
                else:
                    if isinstance(schema, str):
                        schema = [schema]
                    schemas = []
                    for _schema in schema:
                        schemas.append(get_schema(_schema))
                for _schema in schemas:
                    _schema_should += _schema['core'] + _schema['ext']

            _filter = {"bool": {"must": [{"bool": {"should": _schema_should}},
                                         _filter]}}
        kwargs['body'] = {"query": {"bool": {"must": kwargs['body']['query'],
                                             "filter": _filter}}}
        return super().search(**kwargs)

    def index(self, user_id, up_version=True, **kwargs):
        """Wrapper for the elasticsearch ``search()`` method. Overloads the
        existing elasticsearch index() method with stix2 version control.

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            objects (:obj:`list` of :obj:`dict`): List of JSON serializable
                stix2 object dictionaries.
            up_version (:obj:`bool`, optional): Pass through to index() to
                determine if stix up-versioning should be applied.
            **kwargs: As per elasticsearch ``index()`` arguments.

        Returns:
            :obj:`list` of :obj:`str`: List of indexed objects (either the
            objects originally submitted or the newly created objects if
            up-versioning occurs).
        """
        obj_id_parts = kwargs['body']['id'].split('--')
        index_name = obj_id_parts[0]
        doc_id = obj_id_parts[1]

        if 'index' not in kwargs:
            kwargs['index'] = index_name
        if 'id' not in kwargs:
            kwargs['id'] = doc_id
        if 'refresh' not in kwargs:
            kwargs['refresh'] = False
        if not self.exists(index=index_name,
                           id=doc_id,
                           _source=False,
                           ignore=[400, 404]):
            res = super().index(**kwargs)
            if res['result'] == 'created':
                return kwargs['body']['id']
            return False

        if not up_version:
            return False

        new_objs = new_obj_version(user_id=user_id, stix_object=kwargs['body'])
        if (not self.index(user_id=user_id, body=new_objs[0]) or
                not self.index(user_id=user_id, body=new_objs[1])):
            print('Error indexing up version')
            return False
        insert = {"doc": {"revoked": True}}
        res = self.update(index=index_name, id=doc_id, body=insert)
        if res['result'] != 'updated' and res['result'] != 'noop':
            print('Failed to revoke updated object.')
            return False
        return [new_objs[1]['id']]

    def index_objects(self, user_id, objects, up_version=True, refresh=False):
        """Wrapper for the ``index()`` method to handle a list of objects.

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            objects (:obj:`list` of :obj:`dict`): List of JSON serializable
                stix2 object dictionaries.
            up_version (:obj:`bool`, optional): Pass through to index() to
                determine if stix up-versioning should be applied.
            refresh (:obj:`bool`, optional): Pass through to core elasticsearch
                index() function to determine the refresh policy.
        """
        if isinstance(objects, list):
            last_obj = objects.pop(0)
            id_list = []
            for obj in objects:
                res = self.index(user_id=user_id, up_version=up_version,
                                 body=obj, refresh=False)
                if res:
                    id_list.append(res)
            # Honour refresh on the last object
            res = self.index(user_id=user_id, up_version=up_version,
                             body=last_obj, refresh=refresh)
            if res:
                id_list.append(res)
            return id_list
        return self.index(user_id=user_id, up_version=up_version,
                          body=objects, refresh=refresh)

    def store_core_data(self):
        """Should be run once for setup of the necessary CTI core data to turn
        elasticsearch in to a CTI repository.

        Does the following:

        - runs ``__setup_es()`` to setup an index for each supported stix2 type
          (taken from the stix2 python API) with appropriate field mappings
        - stores full 'system' identity objects in elasticsearch that are
          required to resolve references for objects created by the system (eg:
          core marking definitions)
        - stores marking definitions, including base TLP, PII and licences
        - stores location objects as per the UN M49 standard.
        """
        self.__setup_es(self.stix_ver)
        system_id = get_system_id()
        org_id = get_system_org(self.identity['id'])
        if not self.index_objects(user_id=self.identity['id'],
                                  objects=system_id):
            print('Could not store system id.')
            return False
        if not self.index_objects(user_id=self.identity['id'], objects=org_id):
            print('Could not store system org id.')
            return False

        org_rel = get_system_to_org(system_id=self.identity['id'],
                                    org_id=self.org['id'])
        if not self.index(user_id=self.identity['id'], body=org_rel):
            print('Could not store system-org relationship.')
            return False

        markings, os_group_id = get_marking_definitions(self.identity['id'])
        if self.os_group_id == os_group_id:
            if not self.index_objects(user_id=self.identity['id'],
                                      objects=markings):
                print('Could not store marking definitions.')
                return False

        locations = get_locations(self.identity['id'])
        if not self.index_objects(user_id=self.identity['id'],
                                  objects=locations):
            print('Could not store locations.')
            return False
        return True

    def update_md(self, md_obj):
        """Call this when a new marking definition is created to resolve user
        index alias filters for all ids named in the distribution (at the
        moment, very much tlp+ specific as others do not have distribution
        lists). This is the opposite functionality to get_id_markings which is
        called in the user context (and so updates for the specific user only).

        .. note::

            If the user that is named in the distribution list has an index
            alias already created for them (ie: has run a query already and
            triggered ``get_id_markings()``) then this function will update the
            existing index alias in situ and not change the name of the alias
            (ie: does not update the timeslice component). If no index aliases
            exist for those users this function does nothing as the index alias
            filters will be created by get_id_markings() when the user runs
            their first query.

        Args:
            md_obj (:obj:`dict`): TLP+ object to be applied.

        Returns:
            :obj:`bool`: ``True`` for either having successfully applied the
            marking definition or not finding any distribution lists to apply;
            ``False`` if the object is not the correct type.
        """
        # Check to see if there are named distros. Only set for tlp+ atm
        if not md_obj['definition_type'] == 'tlp-plus':
            return False

        aliases_info = self.cat.aliases(format='json')

        done_aliases = []
        md_add = {"match": {"object_marking_refs": md_obj['id']}}
        for user_id in md_obj['definition']['distribution_refs']:
            for alias_info in aliases_info:
                if not re.match(r'.+--' + re.escape(user_id.split('--')[1]) + r'--+',
                                alias_info['alias']):
                    continue
                if alias_info['alias'] not in done_aliases:

                    res = self.indices.get_alias(name=alias_info['alias'])
                    for key in res:
                        _filter = res[key]['aliases'][alias_info['alias']]
                        new_filter = _filter['filter']['bool']['should'].append(md_add)
                        self.indices.put_alias(index=key,
                                               name=alias_info['alias'],
                                               body=new_filter)
                done_aliases.append(alias_info['alias'])
        return True

    def set_tlpplus(self, user_id, md_name, tlp_marking_def_ref,
                    distribution_refs):
        """Creates and stores a tlp+ marking definition object for a named
        distribution list. Also calls ``update_md()`` to proactively update the
        user index aliases of all users named in ``distribution_refs``.

        .. note::

            This function should be called whenver a tlp+ marking definition is
            created to ensure that the database and distribution lists are
            updated. TLP+ objects can be made asynchronously but the effects of
            the distribution list may not be availabe to users straight away if
            not implemented through this method.

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            md_name (:obj:`str`): Free text string for the name of the tlp+
                marking definition.
            tlp_marking_def_ref (:obj:`str`): STIX2 identity object reference
                id for the TLP marking definition (RED or AMBER) to which the
                tlp+ marking definition refers.
            distribution_refs (:obj:`list` of :obj:`str`): List of STIX2
                identity object reference ids for the named user/organisation
                distribution list for the markin definition.

        Returns:
            :obj:`str`: STIX2 identity object reference id for the tlp+ marking
            definition.
        """
        if user_id.split('--')[0] != 'identity':
            return False
        if not isinstance(distribution_refs, list):
            return False
        if (tlp_marking_def_ref != stix2.TLP_AMBER.id and
                tlp_marking_def_ref != stix2.TLP_RED.id):
            return False
        ref_list = distribution_refs[:]
        distribution_refs.append(tlp_marking_def_ref)
        distribution_refs.append(md_name)
        distribution_refs = sorted(set(distribution_refs))
        md_id = get_deterministic_uuid(prefix='marking-definition--',
                                       seed=str(distribution_refs))
        if self.exists(index='marking-definition',
                       id=md_id.split('--')[1],
                       _source=False,
                       ignore=[400, 404]):
            return md_id,
        tlp_plus = TLPPlusMarking(tlp_marking_def_ref=tlp_marking_def_ref,
                                  distribution_refs=ref_list)
        new_md = stix2.v21.MarkingDefinition(name=md_name,
                                             definition_type='tlp-plus',
                                             definition=tlp_plus,
                                             id=md_id,
                                             created_by_ref=user_id)
        md_json = json.loads(new_md.serialize())
        if not self.index_objects(user_id=user_id, objects=md_json,
                                  refresh='wait_for'):
            return False

        if not self.update_md(md_json):
            return False
        return md_id, md_json

    def set_new_osdm(self, user_id, stix_id):
        """Add a stix2 marking definition id reference to the master grouping
        object reference list to be considered viewable by all platform
        users (eg: a copyright statement marking definition which shouldn't
        restrict viewing of the object, just ensure that users are aware of
        it's usage limitations).

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            stix_id (:obj:`str`): marking definition id reference to be added.
        """
        os_group = self.get_object(user_id=user_id, obj_id=self.os_group_id)
        if stix_id in os_group['object_refs']:
            return True
        os_group['object_refs'].append(stix_id)

        res = self.index(user_id=user_id, body=os_group, refresh='wait_for')
        self.os_group_id = res[0]
        return res[0]

    # GETS:
    def get_id_markings(self, user_id, index_alias, force_refresh=False):
        """Creates a new alias for a user that includes a filter of what they
        are allowed to see based on the marking definitions of the data.

        Including:

        - objects with no marking references
        - objects with _only_ os references (eg: TLP WHITE/GREEN)
        - objects with a marking reference that explicitely includes their
          id in a distribution list (eg: tlp+)
        - PII marked objects that are within their org chart

        .. note::

            This method should continue to be used when accessing data in the
            database despite the proactive nature of ``update_md()`` to account
            for the fact that other global users might add a marking definition
            that includes the user in a specific distribution list and may have
            done so without running ``update_md()`` (eg: if someone created a
            tlp+ marking definition offline/manually and just pushed it in as
            an object). Keeping this function on an hourly time slice is 'belt
            and bracers' to catch any updates. It still only updates hourly but
            in scenarios such as the one described the change is asynchronous,
            so unlikely to cause too many usability issues. If search speed is
            willing to be sacrificed over accuracy in these cases, enable
            ``force_refresh``.

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            index_alias (:obj:`str`): The index string being used in the query
                (that will have the alias filter).
            force_refresh (:obj:`bool`): Even if an existing filter is found,
                refresh it anyway (useful if you suspect that a new marking
                definition has been applied that might be applicable to the
                user - but much slower as index alises have to be rebuilt).

        Returns:
            :obj:`str`: User and time specific alias to be used as the new
            index for the query.
        """
        md_alias_root, md_alias_date = md_time_index(user_id=user_id,
                                                     old_alias=index_alias)
        md_alias_name = md_alias_root + '--' + md_alias_date
        if not force_refresh:
            if self.indices.exists_alias(name=md_alias_name):
                return md_alias_name

        self.indices.delete_alias(index='_all',
                                  name=[md_alias_root + '*'],
                                  ignore=[400, 404])
        os_list = self.get_object(user_id=self.identity['id'],
                                  obj_id=self.os_group_id,
                                  _md=False)['object_refs']
        valid_refs = [{"bool": {"must_not": {"exists": {
                                            "field": "object_marking_refs"}}}}]
        for os_id in os_list:
            valid_refs.append({"match": {
                                "object_marking_refs": os_id.split('--')[1]}})

        user_id_split = user_id.split('--')[1]

        # Get orgs that are in the user network from which they may inherit
        #   a distribution list ref (eg: marked TLP AMBER/RED for a whole org)
        q = {"query": {"bool": {"should": [
                                {"match": {"type": 'identity'}},
                                {"match": {"type": "relationship"}}]}}}
        org_objs = self.get_molecule(user_id=user_id,
                                     stix_ids=[user_id],
                                     schema_name='org',
                                     query=q,
                                     objs=True,
                                     _md=False,
                                     pivot=True)
        org_should = [{"match": {
                        "definition.distribution_refs": user_id_split}}]
        for org in org_objs:
            org_id = org['id']
            if org['type'] == 'organization':
                org_should.append({"match": {"definition.distribution_refs":
                                   org_id.split('--')[1]}})
            valid_refs.append(
                {"bool": {"must": [
                    {"match": {"id": org_id.split('--')[1]}},
                    {"match": {"object_marking_refs":
                               self.pii_marking['id'].split('--')[1]}}
                ]}})
        q = {"query": {"bool": {"should": org_should}}}
        res = self.search(user_id=user_id,
                          index='marking-definition',
                          body=q,
                          filter_path=['hits.hits._source.id'],
                          _md=False)
        if res:
            for hit in res['hits']['hits']:
                valid_refs.append({"match": {"object_marking_refs":
                                  hit['_source']['id'].split('--')[1]}})
        body = {"filter": {"bool": {"should": valid_refs}}}
        alias_info = self.cat.aliases(name=index_alias, format='json')
        alias_mapping = []
        for info in alias_info:
            alias_mapping.append(info['index'])
        self.indices.put_alias(index=alias_mapping,
                               name=md_alias_name,
                               body=body)
        pprint(body)
        return md_alias_name

    def get_free_text(self, user_id, phrase, schema=None):
        """EXAMPLE IMPLEMENTATION OF g4i. Takes a string query and conducts a
        full text search of the repository (or a molecule filter).

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            phrase (:obj:`str`): String to be searched for.
            schema (:obj:`str` name or :obj:`dict` object, optional):
                Elasticsearch query to represent the 'molecule' of stix2
                objects as a filter to include objects that represent an
                intelligence category (eg: incident data as a cluster of stix
                objects).

        Returns:
            :obj:`list` of :obj:`dict`: List of JSON serializable stix2 objects
            that meet the query criteria.
        """
        output = []
        q = {"query": {"multi_match": {"query": phrase}}}
        res = self.search(user_id=user_id, body=q)
        if not res['hits']['hits']:
            return False
        if not schema:
            for hit in res['hits']['hits']:
                output.append(hit['_source'])
            return output

        for hit in res['hits']['hits']:
            hit_row = [hit['_source']]
            molecule = self.get_molecule(user_id=user_id,
                                         stix_ids=[hit['_source']['id']],
                                         schema_name=schema,
                                         objs=True,
                                         pivot=False)
            if molecule:
                hit_row.append(molecule)
            output.append(hit_row)
        return output

    def get_object(self, user_id, obj_id, _md=True, values=None):
        """Wrapper for the ``get_objects()`` function to get an object from
        it's stix id.

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            obj_id (:obj:`str`): STIX2 object reference id for the object to
                get.
            _md (:obj:`bool`, optional): Defaults to ``True`` to ensure that
                users are only able to see data in the results that they are
                allowed to as per stix2 marking definitions (md). Should only
                be set to ``False`` for zero-knowledge searches with
                appropriate anonymisation (eg: user searching for organisation
                members requires a join on the organisations they are a member
                of first before they can find out if they are allowed to see
                the data).
            values (:obj:`list` of :obj:`str`, optional): List of phrases to
                perform in-situ free text search.

        Returns:
            :obj:`dict`: JSON serializable python dictionary of the stix2
            object.
        """
        if not isinstance(obj_id, str):
            return False
        docs = self.get_objects(user_id=user_id,
                                obj_ids=[obj_id],
                                values=values,
                                _md=_md)
        if not docs:
            print('No docs found.')
            return False
        if len(docs) > 1:
            print('Multiple docs found (not handled atm).')
            return False
        return docs[0]

    def get_objects(self, user_id, obj_ids, _md=True, values=None):
        """Gets objects from the repository from a list of stix2 reference ids.

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            obj_ids (:obj:`list` of :obj:`str`): STIX2 object reference ids for
                the objects to get.
            _md (:obj:`bool`, optional): Defaults to ``True`` to ensure that
                users are only able to see data in the results that they are
                allowed to as per stix2 marking definitions (md). Should only
                be set to ``False`` for zero-knowledge searches with
                appropriate anonymisation (eg: user searching for organisation
                members requires a join on the organisations they are a member
                of first before they can find out if they are allowed to see
                the data).
            values (:obj:`list` of :obj:`str`, optional): List of phrases to
                perform in-situ free text search.

        Returns:
            :obj:`list` of :obj:`dict`: List of JSON serializable python
            dictionaries of the stix2 objects.
        """
        if not obj_ids:
            return False
        if user_id.split('--')[0] != 'identity':
            return False

        docs = []
        if values:
            if not isinstance(values, list):
                return False
            q = {"query": {"bool": {"must": []}}}
            id_q = {"bool": {"should": []}}
            for obj_id in obj_ids:
                id_q["bool"]["should"].append(
                                    {"match":
                                        {"id": obj_id.split('--')[1]}})
            value_q = {"bool": {"should": []}}
            for value in values:
                value_q["bool"]["should"].append({"multi_match": {
                                                 "query": value}})

            q["query"]["bool"]["must"].append(value_q)
            q["query"]["bool"]["must"].append(id_q)
            res = self.search(user_id=user_id,
                              body=q)
            try:
                for hit in res['hits']['hits']:
                    docs.append(hit['_source'])
            except KeyError:
                return False
            return docs

        g = {"docs": []}
        for obj_id in obj_ids:
            id_parts = obj_id.split('--')
            _index = id_parts[0]
            _id = id_parts[1]
            if _md:
                md_alias = self.get_id_markings(user_id=user_id,
                                                index_alias=_index)
                _index = md_alias
            g['docs'].append({"_index": _index, "_id": _id})

        res = self.mget(body=g)
        try:
            for doc in res['docs']:
                docs.append(doc['_source'])
        except KeyError:
            return False
        return docs

    def get_molecule(self, user_id, stix_ids, schema_name, objs=None,
                     query=None, pivot=False, _md=None):
        """From a seed id and using a molecule schema, return all objects that
        comply with that schema.

        If pivot is set to ``True`` (default) the method will keep running on a
        single schema until it exhausts all matches. If it doesn't get any on
        the first try it will stop straight away (since re-runs won't help).

        If pivot is set to ``False`` the method will split the schema in to
        components and search over each component in turn. It will still quit
        if no hits are found on any component, but if it finds some hits then
        it will re-run to see if it can fill the gaps (ie: the id refs it finds
        in run 1 may be applicable to schema components that were skipped
        earlier). Currently set to re-run twice before giving up. This will be
        the hook for partial matches for further analysis.

        .. note::

            With pivot set to ``False``, so long as the search results grow on
            each iteration, the method will trust that your molecule is going
            somewhere. However, if your molecule is very linear and/or you pick
            a seed id that is on the edge of the molecule, this will result in
            multiple retries and degrade performance. To optimise performance,
            select a seed id for an object that is central to a molecule (eg:
            has more than 1 relationship) to ensure that the id list grows at a
            healthy rate.

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            stix_ids (:obj:`list` of :obj:`str`): STIX2 object reference ids
                as seed object references for the molecule.
            schema (:obj:`str` name or :obj:`dict` object, optional):
                Elasticsearch query to represent the 'molecule' of stix2
                objects as a filter to include objects that represent an
                intelligence category (eg: incident data as a cluster of stix
                objects).
            objs (:obj:`bool`, optional): ``True`` to return full objects;
                ``False`` to return id references only (faster).
            query (:obj:`dict`, optional): Elasticsearch compliant query that
                will be applied as an *and* for the moleule search.
            pivot (:obj:`bool`, optional): ``True`` to allow pivoting to other
                molecules of the same schema (eg: where another incident
                molecule shares an assigned user); ``False`` (default) breaks
                down the query schema to ensure only the targeted object's
                molecule is returned.
            _md (:obj:`bool`, optional): Defaults to ``True`` to ensure that
                users are only able to see data in the results that they are
                allowed to as per stix2 marking definitions (md). Should only
                be set to ``False`` for zero-knowledge searches with
                appropriate anonymisation (eg: user searching for organisation
                members requires a join on the organisations they are a member
                of first before they can find out if they are allowed to see
                the data).

        Returns:
            :obj:`list` of :obj:`dict`: List of JSON serializable python
            dictionaries of the stix2 objects.
        """
        if _md is None:
            _md = True
        if not isinstance(schema_name, str):
            return False

        if pivot:
            # In pivot mode, just get all objects that could be relevant (core
            #   and ext)
            schema_template = get_schema(schema_name)
            should_list = schema_template['core'] + schema_template['ext']
            schemas = {"core": [{"bool": {"should": should_list}}]}
        else:
            # In non-pivot, just get core now, but 
            schema_data = get_schema(schema_name)
            schemas = {"core": schema_data['core'], "ext": schema_data['ext']}
        check_lst = {'core': [], 'ext': []}

        failed = 0
        ids = stix_ids[:]
        ext_ids = []
        while True:
            old_len = len(ids)
            q_ids = []
            q_str = ''
            for _id in ids:
                q_ids.append({"match": {"id": _id.split('--')[1]}})
                q_str += _id.split('--')[1] + " OR "
            q_str = q_str[:-4]

            q_ids.append({"query_string": {
                            "fields": ["*_ref", "*_refs"],
                            "query": q_str}})
            q = {"query": {"bool": {"must": {"bool": {"should": q_ids}}}}}
            count = 0
            for key in schemas:
                for schema in schemas[key]:
                    try:
                        if check_lst[key][count] is True and not pivot:
                            count += 1
                            continue
                    except IndexError:
                        pass
                    res = self.search(user_id=user_id,
                                      body=q,
                                      schema=schema,
                                      _source_excludes=["created_by_ref",
                                                        "object_marking_refs"],
                                      filter_path=['hits.hits._source.id',
                                                   'hits.hits._source.*_ref',
                                                   'hits.hits._source.*_refs'],
                                      _md=_md)
                    try:
                        check_lst[key][count] = bool(res)
                    except IndexError:
                        check_lst[key].append(bool(res))
                    count += 1
                    if res:
                        for hit in res['hits']['hits']:
                            if not pivot and key == 'ext':
                                try:
                                    ext_ids.append(hit['_source']['id'])
                                    continue
                                except KeyError:
                                    pass
                            for value in list(hit['_source'].values()):
                                if isinstance(value, list):
                                    for sub_value in value:
                                        if not sub_value:
                                            continue
                                        ids.append(sub_value)
                                    continue
                                ids.append(value)
            ids = list(set(ids))
            new_len = len(ids)
            if not any(check_lst['core']):
                print('No hits for that schema and seed combination.')
                return False
            if new_len == old_len and all(check_lst['core']) is True:
                # No more growth and hits on all core schema components
                break
            if new_len == old_len and all(check_lst['core']) is False:
                # No more results and still some gaps - worth a rerun...
                failed += 1
            if failed > 2:
                pprint(ids)
                print('Partial molecule matches found, but no full molecules.')
                return False
        if new_len == 1:
            print('Only found the seed object.')
            return False
        if not pivot:
            ids += ext_ids
        if not objs:
            return ids
        q_objs = []
        for _id in ids:
            q_objs.append({"match": {"id": _id.split('--')[1]}})
        if query:
            q = {"query": {"bool": {"must": [query['query'],
                                             {"bool": {"should": q_objs}}]}}}
        else:
            q = {"query": {"bool": {"must": {"bool": {"should": q_objs}}}}}
        res = self.search(user_id=user_id,
                          body=q,
                          schema=schema_name,
                          filter_path=['hits.hits._source'],
                          _md=_md)
        output = []
        if res:
            for hit in res['hits']['hits']:
                output.append(hit['_source'])
        return output

    def get_incidents(self, user_id, focus=None):
        """EXAMPLE IMPLEMENTATION OF g4i. Use the molecule schema method to
        obtain incidents and component phases for a given user and focus.

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.
            focus (:obj:`str`, optional): Focus area, specific to Mission
                Control, for the incident molecules.

        A core concept in understanding "focus" is the organisation structure.
        In this case, where we refer to "the user's organisation" below we
        mean any identity (individual, system or organisation) that the
        user making the request is a member of or that one of those
        identities is also a member of. By this way we understand that a
        user's organisation can also be the parent organisations that their
        company is associated with (eg: ISACs, etc). Importantly, the fact
        that certain identities are affiliated with other identities can
        also be data-marked (using stix marking definitions) to ensure they
        are not included.

        Options for ``focus`` include:

        - *assigned*: that are assigned to the ``user_id``
        - *my_org*: that target the user's organisation
        - *my_sectors*: that target any organisation that shares a sector with
          the user's organisation
        - *my_ao*: that target any identity that shares a geographic region
          with the user's organisation
        - *None*: global search.

        Returns:
            :obj:`list` of :obj:`list` of :obj:`dict`: Nested lists of the
            indicents and their associated phases.
        """
        userid = user_id.split('--')[1]
        seeds = []
        if focus == 'assigned':
            q = {"query": {"bool":
                           {"must":
                            {"match": {"x_eiq_assigned_to_ref": userid}}}}}
            res = self.search(user_id=user_id, index='attack-pattern', body=q,
                              schema='incident',
                              filter_path=['hits.hits._source.id'])
            if not res:
                print('No assigned incidents')
                return False
            for hit in res['hits']['hits']:
                seeds.append(hit['_source']['id'])
        elif focus == 'my_org':
            q = {"query": {"bool":
                           {"must":
                            {"match": {"identity_class": 'organization'}}}}}
            org_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[user_id],
                                         schema_name='org',
                                         query=q,
                                         objs=True,
                                         pivot=True)
            if not org_objs:
                print('No organizations in org chart.')
                return False
            org_ids = []
            for org in org_objs:
                org_id = org['id'].split('--')[1]
                org_ids.append({"match": {"target_ref": org_id}})

            q = {"query": {"bool": {"must": [
                                {"match": {"relationship_type": "targets"}},
                                {"bool": {"should": org_ids}}]}}}
            res = self.search(user_id=user_id, index='relationship', body=q,
                              filter_path=['hits.hits._source.source_ref'])
            if not res:
                print('No incidents targeting your organisation. '
                      'High five your neighbour.')
                return False

            for obj in res['hits']['hits']:
                seeds.append(obj['_source']['source_ref'])
        elif focus == 'my_sectors':
            q = {"query": {"bool": {"must": [
                            {"match": {"identity_class": 'organization'}},
                            {"exists": {"field": "sectors"}}]}}}
            org_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[user_id],
                                         schema_name='org',
                                         query=q,
                                         objs=True,
                                         pivot=True)
            if not org_objs:
                print('No organizations in org chart.')
                return False
            sectors = []
            for obj in org_objs:
                sectors += obj['sectors']
            if not sectors:
                print('No sectors defined on organizations.')
            sectors = list(set(sectors))
            q_sectors = []
            for sector in sectors:
                q_sectors.append({"match": {"sectors": sector}})
            q = {"query": {"bool": {"must": [
                            {"match": {"identity_class": 'organization'}},
                            {"bool": {"should": q_sectors}}]}}}
            # Use an _md False search just to get other org ids only.
            # Technically the org ids are PII, but this is a proportionate
            #   search that only returns ids of orgs with that sector.
            res = self.search(user_id=user_id, index='identity', body=q,
                              filter_path=['hits.hits._source.id'], _md=False)
            if not res:
                print('No incidents in defined sectors.')
                return False
            org_ids = []
            for hit in res['hits']['hits']:
                hit_id = hit['_source']['id'].split('--')[1]
                org_ids.append({"match": {"target_ref": hit_id}})

            q = {"query": {"bool": {"must": [
                                {"match": {"relationship_type": "targets"}},
                                {"bool": {"should": org_ids}}]}}}
            # MDs reapplied here to ensure PII and other markings are respected
            res = self.search(user_id=user_id, index='relationship', body=q,
                              filter_path=['hits.hits._source.source_ref'])
            if not res:
                print('No incidents targeting your sector. '
                      'High five your neighbour.')
                return False

            for obj in res['hits']['hits']:
                seeds.append(obj['_source']['source_ref'])
        elif focus == 'my_ao':
            q = {"query": {"match": {"identity_class": 'organization'}}}
            org_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[user_id],
                                         schema_name='org_geo',
                                         query=q,
                                         objs=True,
                                         pivot=True)
            if not org_objs:
                print('No organizations in geo region.')
                return False
            org_ids = []
            for org in org_objs:
                org_id = org['id'].split('--')[1]
                org_ids.append({"match": {"target_ref": org_id}})

            q = {"query": {"bool": {"must": [
                                {"match": {"relationship_type": "targets"}},
                                {"bool": {"should": org_ids}}]}}}
            res = self.search(user_id=user_id, index='relationship', body=q,
                              filter_path=['hits.hits._source.source_ref'])
            if not res:
                print('No incidents targeting your organisation. '
                      'High five your neighbour.')
                return False

            for obj in res['hits']['hits']:
                seeds.append(obj['_source']['source_ref'])
        else:
            # Assume global
            q = {"query": {"exists": {"field": 'x_eiq_assigned_to_ref'}}}
            res = self.search(user_id=user_id, index='attack-pattern', body=q,
                              filter_path=['hits.hits._source.id'])
            if not res:
                print('No incidents assigned.')
                return False
            for hit in res['hits']['hits']:
                seeds.append(hit['_source']['id'])

        output = []
        for seed in seeds:
            inc_objs = self.get_molecule(user_id=user_id,
                                         stix_ids=[seed],
                                         schema_name='incident',
                                         objs=True,
                                         pivot=False)
            if not inc_objs or len(inc_objs) < 2:
                continue
            inc = inc_objs[:]
            for inc_obj in inc_objs:
                try:
                    if inc_obj['relationship_type'] != 'phase-of':
                        continue
                    phase_objs = self.get_molecule(
                                           user_id=user_id,
                                           stix_ids=[inc_obj['source_ref']],
                                           schema_name='phase',
                                           objs=True,
                                           pivot=False)
                    inc.append(phase_objs)
                except KeyError:
                    pass
            output.append(inc)
        return output

    def get_events(self, user_id):
        """EXAMPLE IMPLEMENTATION OF g4i. Gets event molecules that were
        created by anyone within the user's organisation.

        Args:
            user_id (:obj:`str`): STIX2 identity object reference id for the
                user running the function.

        Returns:
            :obj:`list` of :obj:`list` of :obj:`dict`: Array of event arrays.
            Each event array containing the stix objects fromn the event
            molecule associated with the seed id.
        """
        id_list = []
        org_ids = self.get_molecule(user_id=user_id,
                                    stix_ids=[user_id],
                                    schema_name='org',
                                    pivot=True)
        for org_id in org_ids:
            if org_id.split('--')[0] == 'identity':
                id_list.append({"match": {"created_by_ref":
                                          org_id.split('--')[1]}})
        q = {"query": {"bool": {"should": id_list}}}
        res = self.search(user_id=user_id, index='observed-data', body=q,
                          filter_path=['hits.hits._source.id'])
        seeds = []
        if not res:
            return False
        for hit in res['hits']['hits']:
            seeds.append(hit['_source']['id'])

        output = []
        for seed in seeds:
            res = self.get_molecule(user_id=user_id, stix_ids=[seed],
                                    schema_name='event', pivot=False,
                                    objs=True)
            if res:
                output.append(res)
        return output

    def get_countries(self):
        """Provided for ease of use - provides the full UN M49 country/region
        list as stix2 object id references and their region names.

        Returns:
            :obj:`dict`: Dictionary in the form:
            ``{"country_stix_ref": "country_name"}``
        """
        q = {"query": {"bool": {"must": [
                {"match": {"created_by_ref": self.identity['id']}}],
                "filter": [{"exists": {"field": "country"}}]}}}
        res = self.search(user_id=self.identity['id'],
                          index='location',
                          body=q,
                          _source=['name', 'id'])
        countries = {}
        for hit in res['hits']['hits']:
            countries[hit['_source']['id']] = hit['_source']['name']
        return countries

    # SETUP:
    def __get_index_from_alias(self, index_alias):
        """Supporting function to get the real index names (timestamped,
        specfic stix object typed indices) that are referred to by a given
        alias.

        Args:
            index_alias (:obj:`str`): Alias to be queried.

        Returns:
            :obj:`str`: Index name.
        """
        aliases = self.cat.aliases(name=[index_alias], format='json')
        for alias in aliases:
            if re.match(r'.+--[0-9]+', alias['index']):
                return alias['index']
        return False

    def __update_es_indexmapping(self, index_alias, new_mapping):
        """Updates an index mapping with a new one and swaps over relevant aliases.

        Args:
            index_alias (:obj:`str`): Index alias to be changed.
            new_mapping (:obj:`dict`): JSON serializable python dictionary
                representing the new elasticsearch mapping to be applied to the
                index.

        Returns:
            :obj:`bool`: ``True`` for success; ``False`` if the mapping has
            already been updated in this time window (currently set to the same
            day).
        """
        new_index_name = todays_index(index_alias)

        if self.indices.exists(index=[new_index_name]):
            return False
        else:
            # Strip aliases from old index
            old_index_name = self.__get_index_from_alias(index_alias)
            if old_index_name:
                self.indices.delete_alias(index=[old_index_name], name=[
                    index_alias, 'intel'])
            if index_alias in sdo_indices:
                self.indices.delete_alias(index=[old_index_name], name=['sdo'])

            self.__new_index(index_alias, new_mapping)

            # Reindexing requires at least 1 document in the index...
            num_indices = self.cat.count(index=[new_index_name])
            if int(str(num_indices).split(' ')[2]) > 0:
                reindex_body = {
                    "source": {
                        "index": index_alias
                    },
                    "dest": {
                        "index": new_index_name
                    }
                }
                self.reindex(body=reindex_body)

            return True

    def __new_index(self, index_alias, mapping):
        """Create a new index for the stix object type.

        Args:
            index_alias (:obj:`str`): Index alias to be created.
            mapping (:obj:`dict`): JSON serializable python dictionary
                representing the elasticsearch mapping to be applied to the
                index.

        Returns:
            :obj:`dict`: Elasticsearch response for index creation.
        """
        index_name = todays_index(index_alias)
        self.indices.create(index=index_name, body=mapping)
        self.indices.put_alias(index=[index_name], name='intel')
        if index_alias in sdo_indices:
            self.indices.put_alias(index=[index_name], name='sdo')
        return self.indices.put_alias(index=[index_name], name=index_alias)

    def __setup_es(self, stix_ver):
        """Main harness for setting up elasticsearch indices in accordance with
        the local environment's installed ``stix2`` python API. This can be
        updated in the environment and this harness will ensure that changes in
        the spec (that are in the python API) will get reflected in to the
        index mapping. Specifically this is looking to ensure that property
        types are accurately mapped to improve elasticsearch query performance.

        Args:
            stix_ver (:obj:`str`): Stix version to be applied to the stix2
            python API to determine object composition. Should be either '21'
            or '20'.
        """
        unsupported_types = [
            'archive-ext',
            'bundle',
            'http-request-ext',
            'icmp-ext',
            'language-content',
            'ntfs-ext',
            'pdf-ext',
            'raster-image-ext',
            'socket-ext',
            'statement',
            'tcp-ext',
            'tlp',
            'tlp-plus',
            'unix-account-ext',
            'windows-pebinary-ext',
            'windows-process-ext',
            'windows-registry-value-type',
            'windows-service-ext',
            'x509-v3-extensions-type'
        ]
        module_name = sys.modules[get_stix_ver_name(stix_ver)]
        for name, obj in inspect.getmembers(module_name):
            if not inspect.isclass(obj):
                continue
            try:
                index_name = obj._type
            except AttributeError:
                continue
            if index_name in unsupported_types:
                continue
            new_es_mapping = stix_to_elk(obj, stix_ver)
            tmp_mapping = self.indices.get_mapping(
                index=[index_name], ignore_unavailable=True)

            try:
                current_mapping = next(iter(tmp_mapping.values()))
                if not compare_mappings(current_mapping, new_es_mapping):
                    print(index_name + ' mapping is up to date!')
                    continue
                if not self.__update_es_indexmapping(index_name,
                                                     new_es_mapping):
                    print(index_name +
                          ' was already updated today. Try again tomorrow.')
                    continue
                print('Index refreshed for ' + index_name)
            except StopIteration:
                resp = self.__new_index(index_name, new_es_mapping)
                try:
                    if resp['acknowledged']:
                        print('Created new index for ' + index_name)
                except KeyError:
                    print('Failed to create new index for ' + index_name)

    def data_primer(self):
        """Simple get for the Mitre Att&ck library in stix2.

        Note: We don't apply commit control on ingest - it runs in the
        background so as not to slow down ingestion. If it's stix2.x - let it
        in.

        Returns:
            :obj:`bool`: ``True`` for success; ``False`` if any store action
            failed. (Brutal, I know.)
        """
        attack = {}
        collection = Collection(
            "https://cti-taxii.mitre.org/stix/collections/"
            "95ecc380-afe9-11e4-9b6c-751b66dd541e")
        tc_source = stix2.TAXIICollectionSource(collection)
        attack = tc_source.query()

        for obj in attack:
            try:
                doc = json.loads(obj.serialize())
            except AttributeError:
                doc = obj
            if obj['type'] == 'marking-definition':
                res = self.set_new_osdm(user_id=self.identity['id'],
                                        stix_id=obj['id'])
                print('Added new Mitre Attack os dm: ' + res)
            if not self.index(user_id=self.identity['id'], body=doc):
                return False
        return True
