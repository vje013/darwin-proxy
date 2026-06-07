"""CLI: proxy abstract <input.csv> [-o output.csv] [--k 5]"""
import argparse

from proxy.pipeline import Proxy


def main():
    parser = argparse.ArgumentParser(prog="proxy", description="Darwin Proxy: semantic redaction")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("abstract", help="abstract a CSV")
    a.add_argument("input")
    a.add_argument("-o", "--output", default="abstracted.csv")
    a.add_argument("--k", type=int, default=5, help="k-anonymity threshold")
    a.add_argument("--sample", type=int, default=5)
    args = parser.parse_args()

    if args.command == "abstract":
        proxy = Proxy()
        manifest, rows, out_rows = proxy.abstract_csv(args.input, args.output, k_threshold=args.k)
        _print_report(manifest, rows, out_rows, args.sample)


def _print_report(manifest, rows, out_rows, sample):
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
