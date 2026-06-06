"""Substitution + consistency map. Same original always maps to the same
replacement within a run. Faker provides format-faithful values; the
semantic_class steers the choice toward the right neighborhood.
"""
from faker import Faker
from proxy.classify import REGIONS


class Substitutor:
    def __init__(self, seed=42):
        self.fake = Faker()
        Faker.seed(seed)
        self.maps = {}          # field -> {original: replacement}
        self.entity_map = []    # full original->replacement record (consistency map)

    def _map(self, field):
        return self.maps.setdefault(field, {})

    def substitute(self, field, entity_type, value, semantic_class):
        m = self._map(field)
        if value in m:
            return m[value]
        repl = self._generate(field, entity_type, value, semantic_class)
        m[value] = repl
        return repl

    def _generate(self, field, entity_type, value, sc):
        if entity_type == "PERSON" and field == "First Name":
            g = sc.attributes.get("gender", "unknown")
            if g in ("male", "mostly_male"):
                return self.fake.first_name_male()
            if g in ("female", "mostly_female"):
                return self.fake.first_name_female()
            return self.fake.first_name()
        if entity_type == "PERSON":
            return self.fake.last_name()
        if field == "State":
            region = sc.attributes.get("region")
            if region in REGIONS:
                pool = [s for s in REGIONS[region] if s != value]
                if pool:
                    return self.fake.random_element(pool)
            return self.fake.state()
        if field == "City":
            return self.fake.city()
        if field == "Country":
            return self.fake.country()
        if entity_type == "ORG":
            return self.fake.company()
        return self.fake.word()

    def substitute_format(self, field, entity_type, value):
        m = self._map(field)
        if value in m:
            return m[value]
        repl = self.fake.phone_number() if entity_type == "PHONE" else self.fake.bothify("??-#######")
        m[value] = repl
        return repl

    def derive_email(self, field, value, context):
        m = self._map(field)
        if value in m:
            return m[value]
        first = context.get("First Name", self.fake.first_name())
        last = context.get("Last Name", self.fake.last_name())
        repl = f"{first.lower()}.{last.lower()}@example.com"
        m[value] = repl
        return repl
