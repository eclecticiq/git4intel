import json
import stix2
import sys
import collections
from datetime import datetime
import random
import uuid
from slugify import slugify

hard_loc = "location--3fc1c688-c7e9-4609-ac72-01ac8b4afbc1"


def load_data(path):
    with open(path) as f:
        data = json.load(f)
    return data


def get_deterministic_uuid(prefix=None, seed=None):
    if seed is None:
        stix_id = uuid.uuid4()
    else:
        random.seed(seed)
        a = "%32x" % random.getrandbits(128)
        rd = a[:12] + '4' + a[13:16] + 'a' + a[17:]
        stix_id = uuid.UUID(rd)

    return "{}{}".format(prefix, stix_id)


def get_system_id():
    system_id = stix2.v21.Identity(
                id=get_deterministic_uuid(
                    prefix="identity--",
                    seed='git4intel Setup'),
                identity_class='system',
                name='git4intel Setup',
                sectors=[slugify("IT Consulting & Other Services")])
    loc_rel = stix2.v21.Relationship(
                created_by_ref=system_id.id,
                id=get_deterministic_uuid(
                    prefix="relationship--",
                    seed=(str(system_id.id) +
                          hard_loc +
                          'located_at')),
                source_ref=system_id.id,
                target_ref=hard_loc,
                relationship_type='located_at')
    return stix2.v21.Bundle([system_id, loc_rel])


def get_system_org(system_id):
    org_id = stix2.v21.Identity(
            created_by_ref=system_id,
            id=get_deterministic_uuid(
                prefix="identity--",
                seed='EclecticIQ'),
            identity_class='organization',
            name='EclecticIQ',
            sectors=[slugify("IT Consulting & Other Services")])

    loc_rel = stix2.v21.Relationship(
            created_by_ref=system_id,
            id=get_deterministic_uuid(
                prefix="relationship--",
                seed=(str(org_id.id) +
                      hard_loc +
                      'located_at')),
            source_ref=org_id.id,
            target_ref=hard_loc,
            relationship_type='located_at')
    return stix2.v21.Bundle([org_id, loc_rel])


def get_system_to_org(system_id, org_id):
    org_rel = stix2.v21.Relationship(
            created_by_ref=system_id,
            id=get_deterministic_uuid(
                prefix="relationship--",
                seed=(str(system_id) + str(org_id) + 'relates_to')),
            source_ref=system_id,
            target_ref=org_id,
            relationship_type='relates_to'
    )
    return org_rel


def get_molecules(config_file=None):
    # If user supplied config file
    if config_file:
        with open(config_file, "r") as f:
            return json.loads(f.read())

    # Else return boilerplate
    return {
        "m_hunt": {
            "attack-pattern": {
                "relates_to": ["attack-pattern"]
            },
            "indicator": {
                "indicates": ["attack-pattern"],
                "based_on": ["observed-data"]
            },
            "course-of-action": {
                "mitigates": ["attack-pattern"]
            },
            "malware": {
                "uses": ["attack-pattern"]
            }
        },
        "m_org": {
            "identity": {
                "relates_to": ["identity"],
                "located_at": ["location"]
            },
            "location": {
                "located_at": ["location"]
            }
        }
    }


def refresh_static_data(created_by_ref):
    location_bundle = get_locations(created_by_ref)
    marking_bundle = get_marking_definitions(created_by_ref)
    bundle = stix2.v21.Bundle(location_bundle.objects + marking_bundle.objects)
    return bundle


def update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj


def stixprop_to_field(prop_name, prop):
    schema_map = {
        'ListProperty': {
            'external_references': 'nested',
            'goals': 'text',
            'granular_markings': 'nested',
            'kill_chain_phases': 'nested',
        },
        'StringProperty': {
            'body': 'text',
            'contact_information': 'text',
            'data': 'text',
            'description': 'text',
            'name': 'text',
            'objective': 'text',
            'source_name': 'text',
            'statement': 'text',
            'tool_version': 'text',
            'administrative_area': 'text',
            'city': 'text',
            'street_address': 'text',
            'postal_code': 'text',
            'abstract': 'text',
            'authors': 'text'},
    }

    schema_defaults = {
        'BooleanProperty': 'boolean',
        'EnumProperty': 'keyword',
        'FloatProperty': 'float',
        'HashesProperty': 'keyword',
        'HexProperty': 'keyword',
        'IDProperty': 'tokenized',
        'IntegerProperty': 'integer',
        'ListProperty': 'keyword',
        'MarkingProperty': 'object',
        'ObjectReferenceProperty': 'tokenized',
        'PatternProperty': 'text',
        'ReferenceProperty': 'tokenized',
        'StringProperty': 'keyword',
        'TimestampProperty': 'date',
        'TypeProperty': 'keyword',
        'BinaryProperty': 'binary',
        'ExtensionsProperty': 'object',
        'DictionaryProperty': 'object',
        'EmbeddedObjectProperty': 'object'
    }

    prop_type = type(prop).__name__

    try:
        es_type = schema_map[prop_type][prop_name]
    except KeyError:
        es_type = schema_defaults[prop_type]

    # Override anything ending in _ref or _refs with tokenized
    if prop_name[-5:] == '_refs' or prop_name[-4:] == '_ref':
        es_type = 'tokenized'

    if es_type == 'tokenized':
        return {prop_name: {'type': 'text',
                            "analyzer": "stixid_analyzer"}}
    elif es_type == 'nested':
        out_dict = {prop_name: {'type': 'nested'}}
        for sub_prop in prop.contained._properties:
            update(out_dict, {prop_name: {'properties': stixprop_to_field(
                sub_prop, prop.contained._properties[sub_prop])}})
        return out_dict
    else:
        return {prop_name: {'type': es_type}}


def get_stix_ver_name(stix_ver):
    if stix_ver == '21':
        return stix2.v21.__name__
    else:
        return stix2.v20.__name__


def compare_mappings(current_mapping, new_mapping):
    # Return True if there are differences
    # pprint(current_mapping)
    # pprint(new_mapping)
    for field in new_mapping['mappings']['properties']:
        try:
            if (current_mapping['mappings']['properties'][field] !=
                    new_mapping['mappings']['properties'][field]):
                return True
        except KeyError:
            return True
    return False


def stix_to_elk(obj, stix_ver):
    unsupported_props = [
        'ObservableProperty',
    ]
    index_boilerplate = {
        "settings": {
            "analysis": {
                "analyzer": {
                    "stixid_analyzer": {
                        "tokenizer": "id_split"
                    }
                },
                "tokenizer": {
                    "id_split": {
                        "type": "pattern",
                        "pattern": "--"
                    }
                }
            }

        },
        'mappings': {'properties': {}}
    }
    class_name = obj.__name__
    prop_list = getattr(
        sys.modules[get_stix_ver_name(stix_ver)], class_name)._properties
    mapping = index_boilerplate
    for prop in prop_list:
        prop_type = type(prop_list[prop]).__name__
        if prop_type not in unsupported_props:
            update(mapping['mappings']['properties'], stixprop_to_field(
                prop, prop_list[prop]))
    return mapping


def todays_index(index_alias):
    return (index_alias + '-' + datetime.now().strftime("%y%m%d"))


def get_external_refs(bundle):
    # Returns True if bundle has external refs that are resolvable in
    #   g4i backend
    # Returns False if bundle contains extrefs that are unresolvable
    # Returns None if no extrefs
    rel_lst = []
    id_lst = []
    for obj in bundle.objects:
        for field in obj:
            if field[-4:] == '_ref':
                rel_lst.append(obj[field])
            elif field[-5:] == '_refs':
                for rel in obj[field]:
                    rel_lst.append(rel)
        if obj.type == 'relationship':
            if obj.source_ref not in rel_lst:
                rel_lst.append(obj.source_ref)
            if obj.target_ref not in rel_lst:
                rel_lst.append(obj.target_ref)
        else:
            if obj.id not in id_lst:
                id_lst.append(obj.id)
    diff = list(set(rel_lst) - set(id_lst))
    return diff


def get_marking_definitions(created_by_ref):
    # Install basis marking definitions:
    # - TLP from stix API (except AMBER and RED which need to be extended
    # for named recipient identity ids)
    # - PII for all idents and their relationships (including to locations)
    # required for user creation
    # - Default open source licence for any TLP WHITE/GREEN data

    # Markings with nested objects don't serialise very well...need to fix this
    tlp_white_dm = stix2.v21.common.TLP_WHITE
    tlp_green_dm = stix2.v21.common.TLP_GREEN
    tlp_amber_dm = stix2.v21.common.TLP_AMBER
    tlp_red_dm = stix2.v21.common.TLP_RED

    PII_NIST_EXTREF = stix2.v21.ExternalReference(
        source_name="nist",
        url="https://csrc.nist.gov/glossary/term/"
            "personally-identifiable-information"
    )

    PII_ICO_EXTREF = stix2.v21.ExternalReference(
        source_name="ico",
        url="https://ico.org.uk/for-organisations/guide-to-data-protection/"
            "guide-to-the-general-data-protection-regulation-gdpr/"
            "key-definitions/what-is-personal-data/"
    )

    OS_EXTREF = stix2.v21.ExternalReference(
        source_name="apache-2.0",
        url="https://www.apache.org/licenses/LICENSE-2.0"
    )

    PII_DM = stix2.v21.MarkingDefinition(
        id='marking-definition--d7c85080-576f-4b99-aae3-69d05b2d3bf2',
        created='2019-07-20T00:00:00.000Z',
        created_by_ref=created_by_ref,
        name='Personally Identifiable Information',
        definition_type='statement',
        definition=stix2.v21.StatementMarking(
            statement="Personally identifiable data is stored in this system"
                        " on the legal basis of 'Legtimate Interest'."),
        external_references=[PII_ICO_EXTREF, PII_NIST_EXTREF]
    )

    OS_LICENSE = stix2.v21.MarkingDefinition(
        id='marking-definition--17e2aadf-7b8e-41fb-b70d-18b864b89a64',
        created='2019-07-20T00:00:00.000Z',
        created_by_ref=created_by_ref,
        name='Apache 2.0',
        definition_type='statement',
        definition=stix2.v21.StatementMarking(
            statement="All data submitted to this repository defaults to the "
            "Apache 2.0 open source license unless another license is "
            "explicitly stated by the submittor and/or the data is marked with"
            " community restrictive handling instructions such as "
            "TLP AMBER or RED."),
        external_references=[OS_EXTREF]
    )
    os_licence = OS_LICENSE
    pii_dm = PII_DM

    objs = [
        tlp_red_dm,
        tlp_amber_dm,
        tlp_green_dm,
        tlp_white_dm,
        pii_dm,
        os_licence
    ]
    bundle = stix2.v21.Bundle(objs)
    return bundle


def get_2from3(code3_in):
    # I know it's horrible...trust me.
    code_conv = {
        "BD": "BGD", "BE": "BEL", "BF": "BFA", "BG": "BGR", "BA": "BIH",
        "BB": "BRB", "WF": "WLF", "BL": "BLM", "BM": "BMU", "BN": "BRN",
        "BO": "BOL", "BH": "BHR", "BI": "BDI", "BJ": "BEN", "BT": "BTN",
        "JM": "JAM", "BV": "BVT", "BW": "BWA", "WS": "WSM", "BQ": "BES",
        "BR": "BRA", "BS": "BHS", "JE": "JEY", "BY": "BLR", "BZ": "BLZ",
        "RU": "RUS", "RW": "RWA", "RS": "SRB", "TL": "TLS", "RE": "REU",
        "TM": "TKM", "TJ": "TJK", "RO": "ROU", "TK": "TKL", "GW": "GNB",
        "GU": "GUM", "GT": "GTM", "GS": "SGS", "GR": "GRC", "GQ": "GNQ",
        "GP": "GLP", "JP": "JPN", "GY": "GUY", "GG": "GGY", "GF": "GUF",
        "GE": "GEO", "GD": "GRD", "GB": "GBR", "GA": "GAB", "SV": "SLV",
        "GN": "GIN", "GM": "GMB", "GL": "GRL", "GI": "GIB", "GH": "GHA",
        "OM": "OMN", "TN": "TUN", "JO": "JOR", "HR": "HRV", "HT": "HTI",
        "HU": "HUN", "HK": "HKG", "HN": "HND", "HM": "HMD", "VE": "VEN",
        "PR": "PRI", "PS": "PSE", "PW": "PLW", "PT": "PRT", "SJ": "SJM",
        "PY": "PRY", "IQ": "IRQ", "PA": "PAN", "PF": "PYF", "PG": "PNG",
        "PE": "PER", "PK": "PAK", "PH": "PHL", "PN": "PCN", "PL": "POL",
        "PM": "SPM", "ZM": "ZMB", "EH": "ESH", "EE": "EST", "EG": "EGY",
        "ZA": "ZAF", "EC": "ECU", "IT": "ITA", "VN": "VNM", "SB": "SLB",
        "ET": "ETH", "SO": "SOM", "ZW": "ZWE", "SA": "SAU", "ES": "ESP",
        "ER": "ERI", "ME": "MNE", "MD": "MDA", "MG": "MDG", "MF": "MAF",
        "MA": "MAR", "MC": "MCO", "UZ": "UZB", "MM": "MMR", "ML": "MLI",
        "MO": "MAC", "MN": "MNG", "MH": "MHL", "MK": "MKD", "MU": "MUS",
        "MT": "MLT", "MW": "MWI", "MV": "MDV", "MQ": "MTQ", "MP": "MNP",
        "MS": "MSR", "MR": "MRT", "IM": "IMN", "UG": "UGA", "TZ": "TZA",
        "MY": "MYS", "MX": "MEX", "IL": "ISR", "FR": "FRA", "IO": "IOT",
        "SH": "SHN", "FI": "FIN", "FJ": "FJI", "FK": "FLK", "FM": "FSM",
        "FO": "FRO", "NI": "NIC", "NL": "NLD", "NO": "NOR", "NA": "NAM",
        "VU": "VUT", "NC": "NCL", "NE": "NER", "NF": "NFK", "NG": "NGA",
        "NZ": "NZL", "NP": "NPL", "NR": "NRU", "NU": "NIU", "CK": "COK",
        "XK": "XKX", "CI": "CIV", "CH": "CHE", "CO": "COL", "CN": "CHN",
        "CM": "CMR", "CL": "CHL", "CC": "CCK", "CA": "CAN", "CG": "COG",
        "CF": "CAF", "CD": "COD", "CZ": "CZE", "CY": "CYP", "CX": "CXR",
        "CR": "CRI", "CW": "CUW", "CV": "CPV", "CU": "CUB", "SZ": "SWZ",
        "SY": "SYR", "SX": "SXM", "KG": "KGZ", "KE": "KEN", "SS": "SSD",
        "SR": "SUR", "KI": "KIR", "KH": "KHM", "KN": "KNA", "KM": "COM",
        "ST": "STP", "SK": "SVK", "KR": "KOR", "SI": "SVN", "KP": "PRK",
        "KW": "KWT", "SN": "SEN", "SM": "SMR", "SL": "SLE", "SC": "SYC",
        "KZ": "KAZ", "KY": "CYM", "SG": "SGP", "SE": "SWE", "SD": "SDN",
        "DO": "DOM", "DM": "DMA", "DJ": "DJI", "DK": "DNK", "VG": "VGB",
        "DE": "DEU", "YE": "YEM", "DZ": "DZA", "US": "USA", "UY": "URY",
        "YT": "MYT", "UM": "UMI", "LB": "LBN", "LC": "LCA", "LA": "LAO",
        "TV": "TUV", "TW": "TWN", "TT": "TTO", "TR": "TUR", "LK": "LKA",
        "LI": "LIE", "LV": "LVA", "TO": "TON", "LT": "LTU", "LU": "LUX",
        "LR": "LBR", "LS": "LSO", "TH": "THA", "TF": "ATF", "TG": "TGO",
        "TD": "TCD", "TC": "TCA", "LY": "LBY", "VA": "VAT", "VC": "VCT",
        "AE": "ARE", "AD": "AND", "AG": "ATG", "AF": "AFG", "AI": "AIA",
        "VI": "VIR", "IS": "ISL", "IR": "IRN", "AM": "ARM", "AL": "ALB",
        "AO": "AGO", "AQ": "ATA", "AS": "ASM", "AR": "ARG", "AU": "AUS",
        "AT": "AUT", "AW": "ABW", "IN": "IND", "AX": "ALA", "AZ": "AZE",
        "IE": "IRL", "ID": "IDN", "UA": "UKR", "QA": "QAT", "MZ": "MOZ"}

    for code2, code3 in code_conv.items():
        if code3 == code3_in:
            return code2
    return False


def get_locations(created_by_ref):

    import re

    un_m49 = [
        ['Africa', '', '', '', ''],
        ['Africa', 'Northern Africa', '', '', ''],
        ['Africa', 'Northern Africa', 'Algeria', 'DZA', ''],
        ['Africa', 'Northern Africa', 'Egypt', 'EGY', ''],
        ['Africa', 'Northern Africa', 'Libya', 'LBY', ''],
        ['Africa', 'Northern Africa', 'Morocco', 'MAR', ''],
        ['Africa', 'Northern Africa', 'Sudan', 'SDN', ''],
        ['Africa', 'Northern Africa', 'Tunisia', 'TUN', ''],
        ['Africa', 'Northern Africa', 'Western Sahara', 'ESH', ''],
        ['Africa', 'Sub-Saharan Africa', '', '', ''],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', '', ''],
        ['Africa',
            'Sub-Saharan Africa',
            'Eastern Africa',
            'British Indian Ocean Territory',
            'IOT'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Burundi', 'BDI'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Comoros', 'COM'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Djibouti', 'DJI'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Eritrea', 'ERI'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Ethiopia', 'ETH'],
        ['Africa',
            'Sub-Saharan Africa',
            'Eastern Africa',
            'French Southern Territories',
            'ATF'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Kenya', 'KEN'],
        ['Africa',
            'Sub-Saharan Africa',
            'Eastern Africa',
            'Madagascar',
            'MDG'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Malawi', 'MWI'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Mauritius', 'MUS'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Mayotte', 'MYT'],
        ['Africa',
            'Sub-Saharan Africa',
            'Eastern Africa',
            'Mozambique',
            'MOZ'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Réunion', 'REU'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Rwanda', 'RWA'],
        ['Africa',
            'Sub-Saharan Africa',
            'Eastern Africa',
            'Seychelles',
            'SYC'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Somalia', 'SOM'],
        ['Africa',
            'Sub-Saharan Africa',
            'Eastern Africa',
            'South Sudan',
            'SSD'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Uganda', 'UGA'],
        ['Africa',
            'Sub-Saharan Africa',
            'Eastern Africa',
            'United Republic of Tanzania',
            'TZA'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Zambia', 'ZMB'],
        ['Africa', 'Sub-Saharan Africa', 'Eastern Africa', 'Zimbabwe', 'ZWE'],
        ['Africa', 'Sub-Saharan Africa', 'Middle Africa', '', ''],
        ['Africa', 'Sub-Saharan Africa', 'Middle Africa', 'Angola', 'AGO'],
        ['Africa', 'Sub-Saharan Africa', 'Middle Africa', 'Cameroon', 'CMR'],
        ['Africa',
            'Sub-Saharan Africa',
            'Middle Africa',
            'Central African Republic',
            'CAF'],
        ['Africa', 'Sub-Saharan Africa', 'Middle Africa', 'Chad', 'TCD'],
        ['Africa', 'Sub-Saharan Africa', 'Middle Africa', 'Congo', 'COG'],
        ['Africa',
            'Sub-Saharan Africa',
            'Middle Africa',
            'Democratic Republic of the Congo',
            'COD'],
        ['Africa',
            'Sub-Saharan Africa',
            'Middle Africa',
            'Equatorial Guinea',
            'GNQ'],
        ['Africa', 'Sub-Saharan Africa', 'Middle Africa', 'Gabon', 'GAB'],
        ['Africa',
            'Sub-Saharan Africa',
            'Middle Africa',
            'Sao Tome and Principe',
            'STP'],
        ['Africa', 'Sub-Saharan Africa', 'Southern Africa', '', ''],
        ['Africa', 'Sub-Saharan Africa', 'Southern Africa', 'Botswana', 'BWA'],
        ['Africa', 'Sub-Saharan Africa', 'Southern Africa', 'Eswatini', 'SWZ'],
        ['Africa', 'Sub-Saharan Africa', 'Southern Africa', 'Lesotho', 'LSO'],
        ['Africa', 'Sub-Saharan Africa', 'Southern Africa', 'Namibia', 'NAM'],
        ['Africa',
            'Sub-Saharan Africa',
            'Southern Africa',
            'South Africa',
            'ZAF'],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', '', ''],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', 'Benin', 'BEN'],
        ['Africa',
            'Sub-Saharan Africa',
            'Western Africa',
            'Burkina Faso',
            'BFA'],
        ['Africa',
            'Sub-Saharan Africa',
            'Western Africa',
            'Cabo Verde',
            'CPV'],
        ['Africa',
            'Sub-Saharan Africa',
            'Western Africa',
            'Côte d’Ivoire',
            'CIV'],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', 'Gambia', 'GMB'],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', 'Ghana', 'GHA'],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', 'Guinea', 'GIN'],
        ['Africa',
            'Sub-Saharan Africa',
            'Western Africa',
            'Guinea-Bissau',
            'GNB'],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', 'Liberia', 'LBR'],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', 'Mali', 'MLI'],
        ['Africa',
            'Sub-Saharan Africa',
            'Western Africa',
            'Mauritania',
            'MRT'],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', 'Niger', 'NER'],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', 'Nigeria', 'NGA'],
        ['Africa',
            'Sub-Saharan Africa',
            'Western Africa',
            'Saint Helena',
            'SHN'],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', 'Senegal', 'SEN'],
        ['Africa',
            'Sub-Saharan Africa',
            'Western Africa',
            'Sierra Leone',
            'SLE'],
        ['Africa', 'Sub-Saharan Africa', 'Western Africa', 'Togo', 'TGO'],
        ['Americas', '', '', '', ''],
        ['Americas', 'Latin America and the Caribbean', '', '', ''],
        ['Americas', 'Latin America and the Caribbean', 'Caribbean', '', ''],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Anguilla',
            'AIA'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Antigua and Barbuda',
            'ATG'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Aruba',
            'ABW'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Bahamas',
            'BHS'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Barbados',
            'BRB'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Bonaire, Sint Eustatius and Saba',
            'BES'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'British Virgin Islands',
            'VGB'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Cayman Islands',
            'CYM'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Cuba',
            'CUB'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Curaçao',
            'CUW'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Dominica',
            'DMA'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Dominican Republic',
            'DOM'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Grenada',
            'GRD'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Guadeloupe',
            'GLP'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Haiti',
            'HTI'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Jamaica',
            'JAM'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Martinique',
            'MTQ'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Montserrat',
            'MSR'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Puerto Rico',
            'PRI'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Saint Barthélemy',
            'BLM'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Saint Kitts and Nevis',
            'KNA'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Saint Lucia',
            'LCA'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Saint Martin (French Part)',
            'MAF'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Saint Vincent and the Grenadines',
            'VCT'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Sint Maarten (Dutch part)',
            'SXM'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Trinidad and Tobago',
            'TTO'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'Turks and Caicos Islands',
            'TCA'],
        ['Americas',
            'Latin America and the Caribbean',
            'Caribbean',
            'United States Virgin Islands',
            'VIR'],
        ['Americas',
            'Latin America and the Caribbean',
            'Central America',
            '',
            ''],
        ['Americas',
            'Latin America and the Caribbean',
            'Central America',
            'Belize',
            'BLZ'],
        ['Americas',
            'Latin America and the Caribbean',
            'Central America',
            'Costa Rica',
            'CRI'],
        ['Americas',
            'Latin America and the Caribbean',
            'Central America',
            'El Salvador',
            'SLV'],
        ['Americas',
            'Latin America and the Caribbean',
            'Central America',
            'Guatemala',
            'GTM'],
        ['Americas',
            'Latin America and the Caribbean',
            'Central America',
            'Honduras',
            'HND'],
        ['Americas',
            'Latin America and the Caribbean',
            'Central America',
            'Mexico',
            'MEX'],
        ['Americas',
            'Latin America and the Caribbean',
            'Central America',
            'Nicaragua',
            'NIC'],
        ['Americas',
            'Latin America and the Caribbean',
            'Central America',
            'Panama',
            'PAN'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            '',
            ''],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Argentina',
            'ARG'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Bolivia (Plurinational State of)',
            'BOL'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Bouvet Island',
            'BVT'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Brazil',
            'BRA'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Chile',
            'CHL'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Colombia',
            'COL'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Ecuador',
            'ECU'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Falkland Islands (Malvinas)',
            'FLK'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'French Guiana',
            'GUF'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Guyana',
            'GUY'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Paraguay',
            'PRY'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Peru',
            'PER'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'South Georgia and the South Sandwich Islands',
            'SGS'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Suriname',
            'SUR'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Uruguay',
            'URY'],
        ['Americas',
            'Latin America and the Caribbean',
            'South America',
            'Venezuela (Bolivarian Republic of)',
            'VEN'],
        ['Americas', 'Northern America', 'South America', '', ''],
        ['Americas', 'Northern America', 'Bermuda', 'BMU', ''],
        ['Americas', 'Northern America', 'Canada', 'CAN', ''],
        ['Americas', 'Northern America', 'Greenland', 'GRL', ''],
        ['Americas',
            'Northern America',
            'Saint Pierre and Miquelon',
            'SPM',
            ''],
        ['Americas',
            'Northern America',
            'United States of America',
            'USA',
            ''],
        ['Americas', 'Northern America', 'Antarctica', 'ATA', ''],
        ['Asia', '', '', '', ''],
        ['Asia', 'Central Asia', '', '', ''],
        ['Asia', 'Central Asia', 'Kazakhstan', 'KAZ', ''],
        ['Asia', 'Central Asia', 'Kyrgyzstan', 'KGZ', ''],
        ['Asia', 'Central Asia', 'Tajikistan', 'TJK', ''],
        ['Asia', 'Central Asia', 'Turkmenistan', 'TKM', ''],
        ['Asia', 'Central Asia', 'Uzbekistan', 'UZB', ''],
        ['Asia', 'Eastern Asia', '', '', ''],
        ['Asia', 'Eastern Asia', 'China', 'CHN', ''],
        ['Asia',
            'Eastern Asia',
            'China, Hong Kong Special Administrative Region',
            'HKG',
            ''],
        ['Asia',
            'Eastern Asia',
            'China, Macao Special Administrative Region',
            'MAC',
            ''],
        ['Asia',
            'Eastern Asia',
            "Democratic People's Republic of Korea",
            'PRK',
            ''],
        ['Asia', 'Eastern Asia', 'Japan', 'JPN', ''],
        ['Asia', 'Eastern Asia', 'Mongolia', 'MNG', ''],
        ['Asia', 'Eastern Asia', 'Republic of Korea', 'KOR', ''],
        ['Asia', 'South-eastern Asia', '', '', ''],
        ['Asia', 'South-eastern Asia', 'Brunei Darussalam', 'BRN', ''],
        ['Asia', 'South-eastern Asia', 'Cambodia', 'KHM', ''],
        ['Asia', 'South-eastern Asia', 'Indonesia', 'IDN', ''],
        ['Asia',
            'South-eastern Asia',
            "Lao People's Democratic Republic",
            'LAO',
            ''],
        ['Asia', 'South-eastern Asia', 'Malaysia', 'MYS', ''],
        ['Asia', 'South-eastern Asia', 'Myanmar', 'MMR', ''],
        ['Asia', 'South-eastern Asia', 'Philippines', 'PHL', ''],
        ['Asia', 'South-eastern Asia', 'Singapore', 'SGP', ''],
        ['Asia', 'South-eastern Asia', 'Thailand', 'THA', ''],
        ['Asia', 'South-eastern Asia', 'Timor-Leste', 'TLS', ''],
        ['Asia', 'South-eastern Asia', 'Viet Nam', 'VNM', ''],
        ['Asia', 'Southern Asia', '', '', ''],
        ['Asia', 'Southern Asia', 'Afghanistan', 'AFG', ''],
        ['Asia', 'Southern Asia', 'Bangladesh', 'BGD', ''],
        ['Asia', 'Southern Asia', 'Bhutan', 'BTN', ''],
        ['Asia', 'Southern Asia', 'India', 'IND', ''],
        ['Asia', 'Southern Asia', 'Iran (Islamic Republic of)', 'IRN', ''],
        ['Asia', 'Southern Asia', 'Maldives', 'MDV', ''],
        ['Asia', 'Southern Asia', 'Nepal', 'NPL', ''],
        ['Asia', 'Southern Asia', 'Pakistan', 'PAK', ''],
        ['Asia', 'Southern Asia', 'Sri Lanka', 'LKA', ''],
        ['Asia', 'Western Asia', '', '', ''],
        ['Asia', 'Western Asia', 'Armenia', 'ARM', ''],
        ['Asia', 'Western Asia', 'Azerbaijan', 'AZE', ''],
        ['Asia', 'Western Asia', 'Bahrain', 'BHR', ''],
        ['Asia', 'Western Asia', 'Cyprus', 'CYP', ''],
        ['Asia', 'Western Asia', 'Georgia', 'GEO', ''],
        ['Asia', 'Western Asia', 'Iraq', 'IRQ', ''],
        ['Asia', 'Western Asia', 'Israel', 'ISR', ''],
        ['Asia', 'Western Asia', 'Jordan', 'JOR', ''],
        ['Asia', 'Western Asia', 'Kuwait', 'KWT', ''],
        ['Asia', 'Western Asia', 'Lebanon', 'LBN', ''],
        ['Asia', 'Western Asia', 'Oman', 'OMN', ''],
        ['Asia', 'Western Asia', 'Qatar', 'QAT', ''],
        ['Asia', 'Western Asia', 'Saudi Arabia', 'SAU', ''],
        ['Asia', 'Western Asia', 'State of Palestine', 'PSE', ''],
        ['Asia', 'Western Asia', 'Syrian Arab Republic', 'SYR', ''],
        ['Asia', 'Western Asia', 'Turkey', 'TUR', ''],
        ['Asia', 'Western Asia', 'United Arab Emirates', 'ARE', ''],
        ['Asia', 'Western Asia', 'Yemen', 'YEM', ''],
        ['Europe', '', '', '', ''],
        ['Europe', 'Eastern Europe', '', '', ''],
        ['Europe', 'Eastern Europe', 'Belarus', 'BLR', ''],
        ['Europe', 'Eastern Europe', 'Bulgaria', 'BGR', ''],
        ['Europe', 'Eastern Europe', 'Czechia', 'CZE', ''],
        ['Europe', 'Eastern Europe', 'Hungary', 'HUN', ''],
        ['Europe', 'Eastern Europe', 'Poland', 'POL', ''],
        ['Europe', 'Eastern Europe', 'Republic of Moldova', 'MDA', ''],
        ['Europe', 'Eastern Europe', 'Romania', 'ROU', ''],
        ['Europe', 'Eastern Europe', 'Russian Federation', 'RUS', ''],
        ['Europe', 'Eastern Europe', 'Slovakia', 'SVK', ''],
        ['Europe', 'Eastern Europe', 'Ukraine', 'UKR', ''],
        ['Europe', 'Northern Europe', '', '', ''],
        ['Europe', 'Northern Europe', 'Channel Islands', '', ''],
        ['Europe', 'Northern Europe', 'Channel Islands', 'Guernsey', 'GGY'],
        ['Europe', 'Northern Europe', 'Channel Islands', 'Jersey', 'JEY'],
        ['Europe', 'Northern Europe', 'Channel Islands', 'Sark', ''],
        ['Europe', 'Northern Europe', 'Åland Islands', 'ALA', ''],
        ['Europe', 'Northern Europe', 'Denmark', 'DNK', ''],
        ['Europe', 'Northern Europe', 'Estonia', 'EST', ''],
        ['Europe', 'Northern Europe', 'Faroe Islands', 'FRO', ''],
        ['Europe', 'Northern Europe', 'Finland', 'FIN', ''],
        ['Europe', 'Northern Europe', 'Iceland', 'ISL', ''],
        ['Europe', 'Northern Europe', 'Ireland', 'IRL', ''],
        ['Europe', 'Northern Europe', 'Isle of Man', 'IMN', ''],
        ['Europe', 'Northern Europe', 'Latvia', 'LVA', ''],
        ['Europe', 'Northern Europe', 'Lithuania', 'LTU', ''],
        ['Europe', 'Northern Europe', 'Norway', 'NOR', ''],
        ['Europe',
            'Northern Europe',
            'Svalbard and Jan Mayen Islands',
            'SJM',
            ''],
        ['Europe',
            'Northern Europe',
            'Sweden',
            'SWE',
            ''],
        ['Europe',
            'Northern Europe',
            'United Kingdom of Great Britain and Northern Ireland',
            'GBR',
            ''],
        ['Europe', 'Southern Europe', '', '', ''],
        ['Europe', 'Southern Europe', 'Albania', 'ALB', ''],
        ['Europe', 'Southern Europe', 'Andorra', 'AND', ''],
        ['Europe', 'Southern Europe', 'Bosnia and Herzegovina', 'BIH', ''],
        ['Europe', 'Southern Europe', 'Croatia', 'HRV', ''],
        ['Europe', 'Southern Europe', 'Gibraltar', 'GIB', ''],
        ['Europe', 'Southern Europe', 'Greece', 'GRC', ''],
        ['Europe', 'Southern Europe', 'Holy See', 'VAT', ''],
        ['Europe', 'Southern Europe', 'Italy', 'ITA', ''],
        ['Europe', 'Southern Europe', 'Malta', 'MLT', ''],
        ['Europe', 'Southern Europe', 'Montenegro', 'MNE', ''],
        ['Europe', 'Southern Europe', 'North Macedonia', 'MKD', ''],
        ['Europe', 'Southern Europe', 'Portugal', 'PRT', ''],
        ['Europe', 'Southern Europe', 'San Marino', 'SMR', ''],
        ['Europe', 'Southern Europe', 'Serbia', 'SRB', ''],
        ['Europe', 'Southern Europe', 'Slovenia', 'SVN', ''],
        ['Europe', 'Southern Europe', 'Spain', 'ESP', ''],
        ['Europe', 'Western Europe', '', '', ''],
        ['Europe', 'Western Europe', 'Austria', 'AUT', ''],
        ['Europe', 'Western Europe', 'Belgium', 'BEL', ''],
        ['Europe', 'Western Europe', 'France', 'FRA', ''],
        ['Europe', 'Western Europe', 'Germany', 'DEU', ''],
        ['Europe', 'Western Europe', 'Liechtenstein', 'LIE', ''],
        ['Europe', 'Western Europe', 'Luxembourg', 'LUX', ''],
        ['Europe', 'Western Europe', 'Monaco', 'MCO', ''],
        ['Europe', 'Western Europe', 'Netherlands', 'NLD', ''],
        ['Europe', 'Western Europe', 'Switzerland', 'CHE', ''],
        ['Oceania', '', '', '', ''],
        ['Oceania', 'Australia and New Zealand', '', '', ''],
        ['Oceania', 'Australia and New Zealand', 'Australia', 'AUS', ''],
        ['Oceania',
            'Australia and New Zealand',
            'Christmas Island',
            'CXR',
            ''],
        ['Oceania',
            'Australia and New Zealand',
            'Cocos (Keeling) Islands',
            'CCK',
            ''],
        ['Oceania',
            'Australia and New Zealand',
            'Heard Island and McDonald Islands',
            'HMD',
            ''],
        ['Oceania', 'Australia and New Zealand', 'New Zealand', 'NZL', ''],
        ['Oceania', 'Australia and New Zealand', 'Norfolk Island', 'NFK', ''],
        ['Oceania', 'Melanesia', '', '', ''],
        ['Oceania', 'Melanesia', 'Fiji', 'FJI', ''],
        ['Oceania', 'Melanesia', 'New Caledonia', 'NCL', ''],
        ['Oceania', 'Melanesia', 'Papua New Guinea', 'PNG', ''],
        ['Oceania', 'Melanesia', 'Solomon Islands', 'SLB', ''],
        ['Oceania', 'Melanesia', 'Vanuatu', 'VUT', ''],
        ['Oceania', 'Micronesia', '', '', ''],
        ['Oceania', 'Micronesia', 'Guam', 'GUM', ''],
        ['Oceania', 'Micronesia', 'Kiribati', 'KIR', ''],
        ['Oceania', 'Micronesia', 'Marshall Islands', 'MHL', ''],
        ['Oceania',
            'Micronesia',
            'Micronesia (Federated States of)',
            'FSM',
            ''],
        ['Oceania', 'Micronesia', 'Nauru', 'NRU', ''],
        ['Oceania', 'Micronesia', 'Northern Mariana Islands', 'MNP', ''],
        ['Oceania', 'Micronesia', 'Palau', 'PLW', ''],
        ['Oceania',
            'Micronesia',
            'United States Minor Outlying Islands',
            'UMI',
            ''],
        ['Oceania', 'Polynesia', '', '', ''],
        ['Oceania', 'Polynesia', 'American Samoa', 'ASM', ''],
        ['Oceania', 'Polynesia', 'Cook Islands', 'COK', ''],
        ['Oceania', 'Polynesia', 'French Polynesia', 'PYF', ''],
        ['Oceania', 'Polynesia', 'Niue', 'NIU', ''],
        ['Oceania', 'Polynesia', 'Pitcairn', 'PCN', ''],
        ['Oceania', 'Polynesia', 'Samoa', 'WSM', ''],
        ['Oceania', 'Polynesia', 'Tokelau', 'TKL', ''],
        ['Oceania', 'Polynesia', 'Tonga', 'TON', ''],
        ['Oceania', 'Polynesia', 'Tuvalu', 'TUV', ''],
        ['Oceania', 'Polynesia', 'Wallis and Futuna Islands', 'WLF', ''],
        ['', '', '', '', '']]
    region_ids = []
    all_objs = []
    for row in un_m49:
        row = list(filter(None, row))
        if len(row) > 0:
            for field in row:
                if re.search("[A-Z]{3}", field):
                    # Make Country and relationship to region above
                    country_code = get_2from3(row[-1:][0])
                    country_name = row[-2:-1][0]
                    country_id = get_deterministic_uuid(
                                                prefix="location--",
                                                seed=country_name)
                    country_loc = stix2.v21.Location(
                                                created_by_ref=created_by_ref,
                                                id=country_id,
                                                name=country_name,
                                                country=country_code.lower())
                    all_objs.append(country_loc)
                    upper = -3
                    lower = -2
                    down_loc_id = country_id
                    new_child = True
                    while len(row[upper:lower]) > 0:
                        located_at = row[upper:lower][0]
                        located_at_id = get_deterministic_uuid(
                                                    "location--", located_at)
                        if new_child:
                            rel1 = stix2.v21.Relationship(
                                            created_by_ref=created_by_ref,
                                            id=get_deterministic_uuid(
                                                    prefix="relationship--",
                                                    seed=str(located_at_id +
                                                             down_loc_id +
                                                             'located_at')),
                                            source_ref=down_loc_id,
                                            target_ref=located_at_id,
                                            relationship_type='located_at')
                            all_objs.append(rel1)
                        if located_at_id not in region_ids:
                            region_ids.append(located_at_id)
                            region_loc = stix2.v21.Location(
                                            created_by_ref=created_by_ref,
                                            id=located_at_id,
                                            name=located_at,
                                            region=slugify(located_at))
                            all_objs.append(region_loc)
                            new_child = True
                        else:
                            new_child = False

                        down_loc_id = located_at_id
                        upper -= 1
                        lower -= 1

    bundle = stix2.v21.Bundle(all_objs)
    return bundle
