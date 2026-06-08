# Darwin Proxy

**Destroy the identity. Keep the signal. Prove it.**

Darwin Proxy is a semantic redaction engine for financial AI agents. It strips
identity out of a dataset while preserving the analytical signal, then issues a
signed certificate attesting to what it did and that the result is re-identifiable
below a stated threshold.

## The problem

<<<<<<< HEAD
**What's Next (full product roadmap)**
- Signed Ed25519 attestation certificate proving exactly how data was abstracted (built on Darwin Agentic Cloud)
- K-anonymity re-identification gate validating that no replacement is too rare to be safe
- Chroma vector-based semantic classifier replacing heuristic matching with embedding-space neighborhoods
- Open-core: engine free (Apache-2.0), policy packs and certification paid


# BUILD UPDATE 6/7/2026
Verdict: right now it is a single flat-table, in-memory tool that is not yet schema-flexible. The column policy and the re-id quasi-identifiers are hardcoded to specific English header names.

## What it handles

| Dimension | Current capability |
|---|---|
| Input format | One flat CSV (utf-8-sig) via CLI; CSV text or a JSON list of flat records via the API |
| Structure | Flat rows of string fields. No nested JSON, no multi-table/relational, no Excel/Parquet |
| Row count (validated) | 500 rows real, 2,000 rows logic-only benchmark |
| Throughput | ~765 rows/sec logic-only (blank scanner). Per-record ~1.1 ms, gate ~0.15 ms/row |
| Structured PII (by column) | First/Last name, Email, Business Name, Phone, City, State, Country |
| Inline PII (free text) | SSN, ABA routing, CUSIP, ISIN, EIN, account (checksum/context validated), plus PERSON/ORG/LOCATION via spaCy NER on prose of 3+ tokens |
| Re-id gate | k-anonymity over State, Shares Owned, Acquisition Date, with optimal minimal-loss generalization |
| Output | Abstracted CSV/rows plus an Ed25519-signed certificate |

## Hard limits right now

**Column names are hardcoded.** Semantic replacement only fires on exactly these eight headers: First Name, Last Name, Email, Business Name, Phone Number, City, State, Country. A column called `fname` or `client_first` is treated as signal and kept. Because single-token cells skip NER (the 3-token gate), a `fname` column full of first names passes through largely unredacted. There is no CLI or API way to supply a custom policy yet, even though the engine supports one internally.

**The gate only protects data with its three QI columns.** If a dataset has none of State, Shares Owned, Acquisition Date, the gate finds no quasi-identifiers, puts every record in one class, reports k equal to the row count, and passes with zero generalization. That is a trivial pass with no real re-identification protection, and the certificate will still say passed. This is the most important footgun: the gate is schema-specific, and on the wrong schema it is a no-op that looks like success.

**Everything is in-memory, single-threaded.** `abstract_csv` reads the whole file, abstracts every row, runs the gate over the full set, and writes. No streaming, no chunking, no parallelism. Practical ceiling is low hundreds of thousands of rows before memory and single-thread time bite. The gate is roughly linear in rows but runs many passes during lattice search plus rollback, so it grows with row count.

**Throughput on the real model is unmeasured and lower.** The 765 rows/sec is logic-only with a blank scanner. With the real spaCy model, every signal string cell goes through `analyzer.analyze`, which is much heavier, and free-text prose adds NER cost. Data with several signal columns or any free-text column will run materially slower. I have not benchmarked the real-model path because the model will not download in my sandbox.

**Entity and locale coverage is narrow.** No credit cards, IBAN, IP, street address, DOB, passport, driver license, or any non-US identifiers. Names and org NER are English-centric. The sector corpus is US large-cap only, so funds, LPs, and non-US entities classify to the nearest of seven sectors.

**Input hygiene is thin.** utf-8-sig only. Ragged rows, missing values, or unexpected types are not hardened against; a None in a name field could throw. No size guard, no timeout, no auth, no rate limit on the service.

## The honest one-paragraph summary

It reliably abstracts a clean, flat, English-headered CSV that uses the expected column names, in the low thousands of rows, on a box with the spaCy and Chroma models present, and proves it with a signed certificate. 

The moment the schema drifts from that shape, the column names, the three QI fields, the eight known headers, it quietly does less than it appears to, because unrecognized columns fall through to signal and the gate degrades to a trivial pass. 

The two changes that would most widen its real range are exposing a configurable policy and a configurable QI set through the CLI and API, so it adapts to a customer's actual schema instead of the stockholders schema.
=======
To be useful, a financial AI workflow has to send client data to third-party
models. The moment a client's name, holdings, and account details leave the box,
that is PII egressing to a third party, with the regulatory exposure (GLBA,
Reg S-P, CCPA) landing on the operator. Darwin Proxy strips the identity before
the data leaves, so the model still gets the signal and the real PII never escapes.

## What it does

A dataset flows through four stages:

1. **Detect** which columns carry identity by their *content*, not their header
   names, using a Presidio analyzer with the full predefined recognizer set plus
   checksum-validated finance recognizers (SSN, ABA routing, CUSIP, ISIN, EIN,
   account). Renamed or gibberish headers do not fool it.
2. **Transform** each identifier. The default is keyed, signal-preserving
   substitution: a value maps to the same realistic fake everywhere (a custom
   Presidio operator), so joins and shape survive. An opaque AES-encrypt mode is
   available when nothing analyzable should leave. Geography and dates are kept
   for the gate rather than substituted.
3. **Gate** the result on k-anonymity, generalizing quasi-identifiers (region,
   holdings band, acquisition window) until every record shares its combination
   with at least k others. Quasi-identifiers are inferred from the detected
   entities, and when none are identified the gate refuses to claim k-anonymity
   rather than silently passing.
4. **Certify** with an Ed25519 signature over the manifest, binding the detection
   mapping, operators, locale, reversibility mode, the gate result (including
   whether re-identification risk was actually assessed), and the before/after
   hashes.

Reversibility has two modes: a keyed map (signal-preserving and reversible only
via an encrypted, expiring map) and AES encrypt (opaque and reversible by key
alone). Image inputs are supported optionally via OCR when tesseract is present.

## Quickstart

```bash
pip install darwin-proxy
python -m spacy download en_core_web_lg     # or en_core_web_sm for a lighter box

# abstract a CSV, write output + a signed manifest sidecar next to it
proxy abstract data.csv -o abstracted.csv --k 5

# re-check the certificate against the output (recomputes hash and k)
proxy verify abstracted.csv.manifest.json --output abstracted.csv

# run as a service
proxy serve --port 8000
```

Stable pseudonyms across runs require a persistent key:

```bash
export PROXY_PSEUDONYM_KEY=$(python -c "import os;print(os.urandom(32).hex())")
```

Reversible (map mode) abstraction persists an encrypted, expiring map; reverse
restores the substituted identifiers across the whole table:

```bash
export PROXY_MAP_SECRET='a-high-entropy-secret'
proxy abstract data.csv -o out.csv --mode map --ttl 86400
proxy reverse out.csv -o restored.csv --manifest out.csv.manifest.json --map out.csv.map.enc
```

Opaque, key-only reversibility (no map) uses `--mode encrypt`.

## Performance

Detection (spaCy NER plus the recognizers) is the cost; transform and the gate are
negligible by comparison. Measured on the reference box, detection throughput:

| configuration | rows/s | note |
|---|---|---|
| unbatched (old default) | ~40 | one document at a time |
| batched (current default) | ~137 | ~3.4x, result-identical, no flag needed |
| `--model en_core_web_sm` | ~158 | lighter model, lower NER accuracy |
| `--sample-size 200` | ~1500 | types columns from a sample; may miss sparse PII |
| `--fast` (no NER) | ~380 | pattern-only; skips name/org/location detection |

Guidance. Batching is on by default and changes nothing about the result. For
structured financial data that does not need name/org/location detection, `--fast`
runs pattern-only at several times the speed and records `detection_mode:
pattern-only` in the certificate so the omission is on the record. For large,
homogeneous tables, `--sample-size N` makes detection roughly independent of row
count, at the cost of possibly missing PII that is sparse within a column;
exhaustive (no sampling) is the default precisely because under-detection is the
unsafe direction. `--model en_core_web_sm` trades NER accuracy for speed.

## Trust boundary

The signed manifest is the certificate. There are two roots, one verifier.

| Mode | Who holds the key | `verify` reports | Meaning |
|------|-------------------|------------------|---------|
| Self-signed | the operator's local key | Self-signed (OSS self-attestation) | the output is untampered; the signer is anonymous |
| Darwin-certified | Darwin / DAC authority key only | Darwin-certified (authority root) | a trusted third party vouches |

The engine self-signs for free. Only a manifest whose signer equals the configured
Darwin root verifies as authority-rooted, and only Darwin holds that private key,
so the open-source engine can never forge the stamp. Set `PROXY_DARWIN_ROOT` to the
authority public key to recognize Darwin-certified manifests.

What is independently re-checkable versus what requires the authority:

- **Re-checkable** by anyone holding the output: the signature, the hashes, and the
  k-anonymity claim (recompute the achieved k from the published rows; the `/verify`
  endpoint does this when you pass the rows back).
- **Judgment**, which the authority root vouches for: whether the methodology and
  policy are adequate for a given regulatory regime. De-identification adequacy is a
  statistical argument, not a proof, which is exactly why a certification authority
  has value.

## What this is and is not

Darwin Proxy controls one axis: where identity goes when data leaves the box. It is
one control, not a compliance program. It does not make an operator "compliant"
wholesale. PII mishandling is a civil and regulatory matter, not a criminal one, and
the precise scope of the control is the egress axis.

## API

`POST /abstract` (oneway or encrypt mode), `POST /verify` (re-check a manifest
against a supplied output), `GET /healthz`, `GET /metrics`. The service is
stateless: map mode is not a server concern, since reversing requires a
client-held encrypted map and its secret.

## License

Apache-2.0. Copyright 2026 Darwin Adaptive Systems LLC.
>>>>>>> v2
