"""Semantic classifier. v0 uses gender + US-region heuristics.
Chroma embedding-neighborhood classification replaces this behind the same
SemanticClass output.
"""
import gender_guesser.detector as gender
from proxy.schemas import SemanticClass

_detector = gender.Detector()

REGIONS = {
    "Northeast": ["Connecticut", "Maine", "Massachusetts", "New Hampshire", "Rhode Island",
                  "Vermont", "New Jersey", "New York", "Pennsylvania"],
    "Southeast": ["Alabama", "Arkansas", "Florida", "Georgia", "Kentucky", "Louisiana",
                  "Mississippi", "North Carolina", "South Carolina", "Tennessee", "Virginia",
                  "West Virginia", "Maryland", "Delaware"],
    "Midwest": ["Illinois", "Indiana", "Iowa", "Kansas", "Michigan", "Minnesota", "Missouri",
                "Nebraska", "North Dakota", "Ohio", "South Dakota", "Wisconsin"],
    "Southwest": ["Arizona", "New Mexico", "Oklahoma", "Texas"],
    "West": ["Alaska", "California", "Colorado", "Hawaii", "Idaho", "Montana", "Nevada",
             "Oregon", "Utah", "Washington", "Wyoming"],
}
STATE_TO_REGION = {s: r for r, states in REGIONS.items() for s in states}


class SemanticClassifier:
    def classify(self, field, entity_type, value):
        attrs = {}
        if entity_type == "PERSON" and field == "First Name":
            attrs["gender"] = _detector.get_gender(value)
        if entity_type == "LOCATION" and field == "State":
            attrs["region"] = STATE_TO_REGION.get(value, "unknown")
        return SemanticClass(field=field, entity_type=entity_type, attributes=attrs, radius=1.0)
