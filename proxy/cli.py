"""CLI:
  proxy abstract <input.csv> [-o output.csv] [--k 5] [--cert path] [--key path] [--no-sign]
  proxy verify <cert.json> [--darwin-root HEX]
"""
import argparse

from proxy.pipeline import Proxy
from proxy.cert import load_or_create_key, verify_manifest, DEFAULT_KEY_PATH
from proxy.schemas import AbstractionManifest


def main():
    parser = argparse.ArgumentParser(prog="proxy", description="Darwin Proxy: semantic redaction")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("abstract", help="abstract a CSV and write a signed certificate")
    a.add_argument("input")
    a.add_argument("-o", "--output", default="abstracted.csv")
    a.add_argument("--k", type=int, default=5, help="k-anonymity threshold")
    a.add_argument("--cert", default=None, help="certificate path (default <output>.cert.json)")
    a.add_argument("--key", default=DEFAULT_KEY_PATH, help="Ed25519 signing key (PEM)")
    a.add_argument("--no-sign", action="store_true")
    a.add_argument("--sample", type=int, default=5)

    v = sub.add_parser("verify", help="verify a certificate and report its trust root")
    v.add_argument("cert")
    v.add_argument("--darwin-root", default=None, help="Darwin authority root pubkey (hex)")

    args = parser.parse_args()
    if args.command == "abstract":
        _abstract(args)
    elif args.command == "verify":
        _verify(args)


def _abstract(args):
    proxy = Proxy()
    key = None if args.no_sign else load_or_create_key(args.key)
    manifest, rows, out_rows = proxy.abstract_csv(
        args.input, args.output, k_threshold=args.k, sign=not args.no_sign, key=key)
    cert_path = args.cert or (args.output + ".cert.json")
    if not args.no_sign:
        with open(cert_path, "w") as f:
            f.write(manifest.model_dump_json(indent=2))
    _print_report(manifest, rows, out_rows, args.sample, cert_path if not args.no_sign else None)


def _verify(args):
    with open(args.cert) as f:
        manifest = AbstractionManifest.model_validate_json(f.read())
    r = verify_manifest(manifest, darwin_root=args.darwin_root)
    root_label = {"darwin": "Darwin-certified (authority root)",
                  "self": "Self-signed (OSS self-attestation)",
                  "none": "unverified"}[r["root"]]
    g = manifest.gate_result or {}
    print("=" * 78)
    print("DARWIN PROXY - Certificate Verification")
    print("=" * 78)
    print(f"doc_id:     {manifest.doc_id}")
    print(f"timestamp:  {manifest.timestamp}")
    print(f"signature:  {'VALID' if r['valid'] else 'INVALID'}")
    print(f"trust root: {root_label}")
    print(f"signer:     {r['signer'][:32]}..." if r["signer"] else "signer:     (none)")
    print(f"records:    {manifest.records}")
    if g:
        print(f"gate:       k={g.get('k')} [{'PASS' if g.get('passed') else 'FAIL'}]")
    if manifest.inline_redactions:
        print(f"inline:     {manifest.inline_redactions}")
    raise SystemExit(0 if r["valid"] else 1)


def _print_report(manifest, rows, out_rows, sample, cert_path):
    g = manifest.gate_result or {}
    print("=" * 78)
    print("DARWIN PROXY - Semantic Abstraction Complete")
    print("=" * 78)
    print(f"Records:    {manifest.records}")
    print(f"Abstracted: {', '.join(manifest.fields_abstracted)}")
    print(f"Preserved:  {', '.join(manifest.fields_preserved)}")
    print(f"Before:     {manifest.before_hash[:16]}...")
    print(f"After:      {manifest.after_hash[:16]}...")
    status = "PASS" if g.get("passed") else "FAIL"
    print(f"Re-id gate: k={g.get('k')} (threshold {g.get('threshold')}) [{status}]")
    if g.get("generalized"):
        print(f"Generalized: {g['generalized']}")
    if manifest.inline_redactions:
        print(f"Inline:     {manifest.inline_redactions}")
    if manifest.signature:
        print(f"Signed:     self ({manifest.signer_pubkey[:16]}...)")
        print(f"Cert:       {cert_path}")
    show = ["First Name", "Last Name", "Email", "State", "Shares Owned", "Acquisition Date"]
    show = [s for s in show if rows and s in rows[0]]
    print(f"\nSAMPLE TRANSFORM (first {sample}):")
    print("-" * 78)
    for i in range(min(sample, len(rows))):
        rid = rows[i].get("Stockholder ID", f"row {i}")
        print(f"\n  {rid}:")
        for field in show:
            print(f"    {field:18s} {str(rows[i][field]):26s} -> {out_rows[i][field]}")


if __name__ == "__main__":
    main()
