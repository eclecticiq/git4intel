import stix2
from datetime import datetime
import json
import requests


def main():
    ipv4 = stix2.v21.IPv4Address(value='8.8.8.8')
    domain_name = stix2.v21.DomainName(value='google.com')
    obs_data = stix2.v21.ObservedData(first_observed=datetime.now(
    ), last_observed=datetime.now(), number_observed=1, object_refs=[ipv4.id, domain_name.id])
    atp_hunter = stix2.v21.AttackPattern(
        name="ATP Phase Definition from Hunter")
    ind_event = stix2.v21.Indicator(name="Collection of Observed Data signifying Event", labels=[
                                    'malicious-activity'], pattern="[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019e']", pattern_type='stix', indicator_types=['malicious-activity'])
    rel_obsdata_ind = stix2.v21.Relationship(
        source_ref=ind_event.id, target_ref=atp_hunter.id, relationship_type='indicates')
    rel_atp_mitre = stix2.v21.Relationship(
        source_ref=atp_hunter.id, target_ref='attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add', relationship_type='relates_to')
    rel_ind_obsdata = stix2.v21.Relationship(
        source_ref=ind_event.id, target_ref=obs_data.id, relationship_type='based_on')

    bundle = stix2.v21.Bundle(
        [obs_data, domain_name, ipv4, atp_hunter, ind_event, rel_atp_mitre, rel_obsdata_ind, rel_ind_obsdata])
    # print(bundle.serialize())
    with open('m_hunt.json', 'w') as f:
        f.write(bundle.serialize())

    # print(bundle.serialize())

    # gist_edit = {
    #     "description": "Molecule Examples",
    #     "files": {
    #         "m_hunt.json": {
    #             "content": "a new thing",
    #             "filename": "m_hunt.json"
    #         }
    #     }
    # }

    # res = requests.patch(
    #     url='https://api.github.com/gists/f90871b741fddb57b1c6daa416723799', data=gist_edit)
    # print(res)


if __name__ == "__main__":
    main()
