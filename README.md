**Problem**
- Zo lets anyone build and run a business on AI, including finance (one-person hedge funds, advisory firms, fintech)
- The moment a finance user puts real client data (names, tax IDs, holdings) through Zo, that data gets sent to third-party AI models (OpenAI, Anthropic, MiniMax, etc.)
- That is a compliance violation under GLBA, Reg S-P, and state privacy laws — the liability lands on the user, and Zo's "private by default" claim becomes deceptive
- Without a fix, Zo's highest-value users (regulated finance) can't use the product on real data

**What Darwin Proxy Does**
- Strips identity from sensitive records while preserving the analytical signal they carry
- Names are gender-matched (John → Mark, not John → Danielle)
- Locations stay in-region (Connecticut → Vermont, both Northeast)
- Format-only fields (tax IDs, phone numbers) get structurally valid fakes
- The same real entity always maps to the same fake entity across the entire dataset (consistency map)
- Signal-bearing fields (share class, shares owned, acquisition date) are untouched — the data stays usable for AI

**Architecture**
- Input: raw CSV/record with PII
- Detector: identifies and types every sensitive span (name, email, city, phone, EIN)
- Partitioner: separates identity fields (abstract these) from environment/signal fields (keep these)
- Semantic classifier: characterizes each value by its neighborhood (gender, region, cohort) rather than just its type
- Substitutor: draws a concrete replacement from the same semantic neighborhood, not a random fake
- Consistency map: keyed by entity, ensures the same person/place maps to the same replacement everywhere (reversible in round-trip mode, discardable in one-way mode)
- Output: abstracted CSV + SHA-256 before/after hashes

**Workflow**
- Finance user uploads client data to Zo
- Proxy intercepts before data leaves the box to any third-party model
- Identity is stripped, signal is preserved, replacements are semantically faithful
- The AI model receives usable data with zero real PII
- The user gets AI-powered analysis on their real dataset without ever exposing a real client

**What's Next (full product roadmap)**
- Signed Ed25519 attestation certificate proving exactly how data was abstracted (built on Darwin Agentic Cloud)
- K-anonymity re-identification gate validating that no replacement is too rare to be safe
- Chroma vector-based semantic classifier replacing heuristic matching with embedding-space neighborhoods
- Open-core: engine free (Apache-2.0), policy packs and certification paid


# BUILD UPDATE 6/7/2026
Verdict: right now it is a single flat-table, in-memory tool that is strongest on data shaped like the stockholders file. It is not yet schema-flexible. The column policy and the re-id quasi-identifiers are hardcoded to specific English header names, and that, not file size, is the real constraint.

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

It reliably abstracts a clean, flat, English-headered CSV that uses the expected column names, in the low thousands of rows, on a box with the spaCy and Chroma models present, and proves it with a signed certificate. The moment the schema drifts from that shape, the column names, the three QI fields, the eight known headers, it quietly does less than it appears to, because unrecognized columns fall through to signal and the gate degrades to a trivial pass. The two changes that would most widen its real range are exposing a configurable policy and a configurable QI set through the CLI and API, so it adapts to a customer's actual schema instead of the stockholders schema.
