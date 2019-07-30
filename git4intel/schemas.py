user = {"title": "identity--user",
        "description": "Identity object that must indicate an individual user.",
        "type": "object",
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

user_loc_ref = {"title": "relationship--operatinglocationref",
                "description": "Relationship that indicates the user operating location.",
                "type": "object",
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

register_user = {
    "type": "array",
    "title": "user",
    "description": "User registration including location reference.",
    "maxItems": 2,
    "items": [user, user_loc_ref]
    }

org = {"title": "identity--organization",
       "description": "Identity object that must indicate an organization.",
       "type": "object",
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

org_loc_ref = {"title": "relationship--incoporatedlocref",
               "description": "Relationship that indicates the location that the organization is incorporated at.",
               "type": "object",
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

register_org = {"type": "array",
                "title": "org",
                "description": "Single organization.",
                "maxItems": 2,
                "items": [org, org_loc_ref]}

area_of_operation = {
            "title": "relationship--ao",
            "description": "Relationship that indicates the location that the identity operates at.",
            "type": "object",
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

org_member = {
            "title": "relationship--membership",
            "description": "Relationship that indicates an an identity's membership of an organization.",
            "type": "object",
            "properties": {
                    "type": {
                        "type": "string",
                        "description": "The type of this object, which MUST be the literal `relationship`.",
                        "const": "relationship"
                    },
                    "source_ref": {
                        "description": "The ID of the source (from) object.",
                        "type": "string",
                        "pattern": "^identity--.+$"
                    },
                    "target_ref": {
                        "description": "The ID of the target (to) object.",
                        "type": "string",
                        "pattern": "^identity--.+$"
                    },
                    "relationship_type": {
                        "title": "relationship_type",
                        "type": "string",
                        "description": "The name used to identify the type of relationship.",
                        "const": "member_of"
                    }
            }
        }

event = {
    "title": "event",
    "description": "Mission Control specific structure of observed network observables that the user deems as part of the same event.",
    "type": "array",
    "contains": [
        {"title": "grouping--event",
            "description": "Meta-object that represents the declaration of an event context",
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "const": "grouping"
                },
                "context": {
                    "type": "string",
                    "const": "event"
                },
                "created_by_ref": {
                    "type": "string",
                    "pattern": "^identity--"
                }
            }
        }, {
                "title": "observed-data--event",
                "description": "Observed data conveys information that was observed on systems and networks, such as log data or network traffic, using the Cyber Observable specification.",
                "type": "object"
        }

    ]
}