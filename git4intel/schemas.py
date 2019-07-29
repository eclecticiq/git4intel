user = {
    "type": "array",
    "title": "user",
    "description": "Single user.",
    "maxItems": 2,
    "items": [
        {
            "title": "identity--user",
            "description": "Identity object that must indicate an individual user.",
            "type": "object",
            "allOf": [
                {
                    "properties": {
                        "type": {
                            "type": "string",
                            "description": "The type of this object, which MUST be the literal `identity`.",
                            "const": "identity"
                        },
                        "identity_class": {
                            "type": "string",
                            "description": "The type of entity that this Identity describes, e.g., an individual or organization. Open Vocab - identity-class-ov",
                            "enum": [
                                "individual",
                                "system"
                            ]
                        }
                    }
                }
            ]
        }, {
            "title": "relationship--operatinglocationref",
            "description": "Relationship that indicates the user operating location.",
            "type": "object",
            "allOf": [
                {
                    "properties": {
                        "type": {
                            "type": "string",
                            "description": "The type of this object, which MUST be the literal `relationship`.",
                            "const": "relationship"
                        },
                        "source_ref": {
                            "description": "The ID of the source (from) object.",
                            "allOf": [
                                {"pattern": "^identity--.+$"}
                            ]
                        },
                        "target_ref": {
                            "description": "The ID of the target (to) object.",
                            "allOf": [
                                {"pattern": "^location--.+$"}
                            ]
                        },
                        "relationship_type": {
                            "title": "relationship_type",
                            "type": "string",
                            "description": "The name used to identify the type of relationship.",
                            "const": "operates_at"
                        }
                    }
                }
            ]
        }
    ]
}

org = {
    "type": "array",
    "title": "org",
    "description": "Single organization.",
    "maxItems": 2,
    "items": [
        {
            "title": "identity--organization",
            "description": "Identity object that must indicate an organization.",
            "type": "object",
            "allOf": [
                {
                    "properties": {
                        "type": {
                            "type": "string",
                            "description": "The type of this object, which MUST be the literal `identity`.",
                            "const": "identity"
                        },
                        "identity_class": {
                            "type": "string",
                            "description": "The type of entity that this Identity describes, e.g., an individual or organization. Open Vocab - identity-class-ov",
                            "const": "organization"
                        }
                    }
                }
            ]
        }, {
            "title": "relationship--incoporatedlocref",
            "description": "Relationship that indicates the location that the organization is incorporated at.",
            "type": "object",
            "allOf": [
                {
                    "properties": {
                        "type": {
                            "type": "string",
                            "description": "The type of this object, which MUST be the literal `relationship`.",
                            "const": "relationship"
                        },
                        "source_ref": {
                            "description": "The ID of the source (from) object.",
                            "allOf": [
                                {"pattern": "^identity--.+$"}
                            ]
                        },
                        "target_ref": {
                            "description": "The ID of the target (to) object.",
                            "allOf": [
                                {"pattern": "^location--.+$"}
                            ]
                        },
                        "relationship_type": {
                            "title": "relationship_type",
                            "type": "string",
                            "description": "The name used to identify the type of relationship.",
                            "const": "incorporated_at"
                        }
                    }
                }
            ]
        }
    ]
}

area_of_operation = {
    "type": "array",
    "title": "area_of_operation",
    "description": "List of relationships from identities to locations to define an AO.",
    "items": [
        {
            "title": "relationship--ao",
            "description": "Relationship that indicates the location that the identity operates at.",
            "type": "object",
            "allOf": [
                {
                    "properties": {
                        "type": {
                            "type": "string",
                            "description": "The type of this object, which MUST be the literal `relationship`.",
                            "const": "relationship"
                        },
                        "source_ref": {
                            "description": "The ID of the source (from) object.",
                            "allOf": [
                                {"pattern": "^identity--.+$"}
                            ]
                        },
                        "target_ref": {
                            "description": "The ID of the target (to) object.",
                            "allOf": [
                                {"pattern": "^location--.+$"}
                            ]
                        },
                        "relationship_type": {
                            "title": "relationship_type",
                            "type": "string",
                            "description": "The name used to identify the type of relationship.",
                            "const": "operates_at"
                        }
                    }
                }
            ]
        }
    ]
}

org_member = {
    "type": "array",
    "title": "org_member",
    "description": "List of relationships from identities to locations to define an AO.",
    "items": [
        {
            "title": "relationship--membership",
            "description": "Relationship that indicates an an identity's membership of an organization.",
            "type": "object",
            "allOf": [
                {
                    "properties": {
                        "type": {
                            "type": "string",
                            "description": "The type of this object, which MUST be the literal `relationship`.",
                            "const": "relationship"
                        },
                        "source_ref": {
                            "description": "The ID of the source (from) object.",
                            "allOf": [
                                {"pattern": "^identity--.+$"}
                            ]
                        },
                        "target_ref": {
                            "description": "The ID of the target (to) object.",
                            "allOf": [
                                {"pattern": "^identity--.+$"}
                            ]
                        },
                        "relationship_type": {
                            "title": "relationship_type",
                            "type": "string",
                            "description": "The name used to identify the type of relationship.",
                            "const": "member_of"
                        }
                    }
                }
            ]
        }
    ]
}