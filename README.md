# Darwin Proxy

**Destroy the identity. Keep the signal. Prove it.**

Darwin Proxy is a semantic redaction engine for financial AI agents. It strips
identity out of a dataset while preserving the analytical signal, then issues a
signed certificate attesting to what it did and that the result is re-identifiable
below a stated threshold.

## The problem

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
