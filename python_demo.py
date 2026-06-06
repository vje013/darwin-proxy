"""Darwin Proxy — Hackathon Demo v2
Gender-matched name replacements. Same-region awareness where possible.
"""
import csv
import hashlib
from faker import Faker
import gender_guesser.detector as gender

fake = Faker()
Faker.seed(42)
detector = gender.Detector()

INPUT = "/home/workspace/stockholders_data.csv"
OUTPUT = "/home/workspace/stockholders_abstracted.csv"

# Consistency maps
maps = {
    "First Name": {},
    "Last Name": {},
    "Email": {},
    "Business Name": {},
    "Phone Number": {},
    "City": {},
    "State": {},
    "Country": {},
}

# US region mapping for smarter state replacement
REGIONS = {
    "Northeast": ["Connecticut", "Maine", "Massachusetts", "New Hampshire", "Rhode Island", "Vermont", "New Jersey", "New York", "Pennsylvania"],
    "Southeast": ["Alabama", "Arkansas", "Florida", "Georgia", "Kentucky", "Louisiana", "Mississippi", "North Carolina", "South Carolina", "Tennessee", "Virginia", "West Virginia", "Maryland", "Delaware"],
    "Midwest": ["Illinois", "Indiana", "Iowa", "Kansas", "Michigan", "Minnesota", "Missouri", "Nebraska", "North Dakota", "Ohio", "South Dakota", "Wisconsin"],
    "Southwest": ["Arizona", "New Mexico", "Oklahoma", "Texas"],
    "West": ["Alaska", "California", "Colorado", "Hawaii", "Idaho", "Montana", "Nevada", "Oregon", "Utah", "Washington", "Wyoming"],
}
STATE_TO_REGION = {}
for region, states in REGIONS.items():
    for s in states:
        STATE_TO_REGION[s] = region

def get_same_region_state(original_state):
    """Return a different state in the same US region."""
    region = STATE_TO_REGION.get(original_state)
    if region:
        candidates = [s for s in REGIONS[region] if s != original_state]
        if candidates:
            return fake.random_element(candidates)
    return fake.state()

def get_gendered_first_name(original_name):
    """Return a Faker first name matching the detected gender."""
    g = detector.get_gender(original_name)
    if g in ("male", "mostly_male"):
        return fake.first_name_male()
    elif g in ("female", "mostly_female"):
        return fake.first_name_female()
    return fake.first_name()

KEEP_FIELDS = {"Stockholder ID", "Share Class", "Shares Owned", "Acquisition Date"}

# Read
with open(INPUT, "r", newline="", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames
    rows = list(reader)

# Abstract
abstracted_rows = []

for row in rows:
    new_row = {}

    # First Name: gender-matched
    orig_first = row["First Name"]
    if orig_first not in maps["First Name"]:
        maps["First Name"][orig_first] = get_gendered_first_name(orig_first)
    first_fake = maps["First Name"][orig_first]

    # Last Name: random (ethnicity matching needs a bigger model)
    orig_last = row["Last Name"]
    if orig_last not in maps["Last Name"]:
        maps["Last Name"][orig_last] = fake.last_name()
    last_fake = maps["Last Name"][orig_last]

    # State: same-region replacement
    orig_state = row["State"]
    if orig_state not in maps["State"]:
        maps["State"][orig_state] = get_same_region_state(orig_state)
    state_fake = maps["State"][orig_state]

    for field in fieldnames:
        if field in KEEP_FIELDS:
            new_row[field] = row[field]
        elif field == "First Name":
            new_row[field] = first_fake
        elif field == "Last Name":
            new_row[field] = last_fake
        elif field == "State":
            new_row[field] = state_fake
        elif field == "Email":
            new_row[field] = f"{first_fake.lower()}.{last_fake.lower()}@example.com"
        elif field == "Business Name":
            orig = row[field]
            if orig not in maps[field]:
                maps[field][orig] = fake.company()
            new_row[field] = maps[field][orig]
        elif field == "Phone Number":
            orig = row[field]
            if orig not in maps[field]:
                maps[field][orig] = fake.phone_number()
            new_row[field] = maps[field][orig]
        elif field == "City":
            orig = row[field]
            if orig not in maps[field]:
                maps[field][orig] = fake.city()
            new_row[field] = maps[field][orig]
        elif field == "Country":
            orig = row[field]
            if orig not in maps[field]:
                maps[field][orig] = fake.country()
            new_row[field] = maps[field][orig]
        else:
            new_row[field] = row[field]

    abstracted_rows.append(new_row)

# Write
with open(OUTPUT, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(abstracted_rows)

# Hashes
with open(INPUT, "rb") as f:
    before_hash = hashlib.sha256(f.read()).hexdigest()[:16]
with open(OUTPUT, "rb") as f:
    after_hash = hashlib.sha256(f.read()).hexdigest()[:16]

# Print
print("=" * 80)
print("DARWIN PROXY — Semantic Abstraction Complete")
print("=" * 80)
print(f"Records: {len(rows)}")
print(f"Abstracted: First Name (gender-matched), Last Name, Email, Business, Phone, City, State (same-region), Country")
print(f"Preserved:  Stockholder ID, Share Class, Shares Owned, Acquisition Date")
print(f"Before: {before_hash}...  After: {after_hash}...")
print()

pii_fields = ["First Name", "Last Name", "Email", "State", "City", "Business Name"]
print("SAMPLE TRANSFORM (first 5 records):")
print("-" * 80)
for i in range(min(5, len(rows))):
    print(f"\n  {rows[i]['Stockholder ID']}:")
    for field in pii_fields:
        orig = rows[i][field]
        repl = abstracted_rows[i][field]
        tag = ""
        if field == "First Name":
            g = detector.get_gender(orig)
            tag = f"  [{g}]"
        if field == "State":
            r = STATE_TO_REGION.get(orig, "?")
            tag = f"  [{r}]"
        print(f"    {field:15s}  {orig:30s} → {repl}{tag}")

print()
print(f"Output: {OUTPUT}")
