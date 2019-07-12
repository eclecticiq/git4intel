import feedparser
from pprint import pprint
import stix2
import json


def main():
    url = 'https://www.theregister.co.uk/security/headlines.atom'

    feed = feedparser.parse(url)

    objects = []

    id_elreg = stix2.Identity(
        identity_class='organization', name='The Register')

    # Mock Indicator because I need an object ref for a report...
    ind = stix2.Indicator(labels=['malicious-activity'],
                          pattern="[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']")

    objects.append(id_elreg)
    objects.append(ind)

    author_cache = {}
    for entry in feed['entries']:

        if entry['author'] in author_cache:
            id_author = author_cache[entry['author']]
        else:
            author_obj = stix2.Identity(
                identity_class='individual', name=entry['author'])
            id_author = author_obj.id
            author_cache[entry['author']] = id_author
            objects.append(author_obj)

        id_rep_rel = stix2.Relationship(
            source_ref=id_author, target_ref=id_elreg, relationship_type='relatd-to')
        report = stix2.Report(
            name=entry['title'], labels=['threat-report'], object_refs=[ind.id], published=entry['updated'], created_by_ref=id_author)

        objects.append(id_rep_rel)
        objects.append(report)

    bundle = stix2.Bundle(objects)

    print(bundle)
    # with open('data.json', 'w') as f:
    #     json.dump(bundle, f)


if __name__ == "__main__":
    main()
