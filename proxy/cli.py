"""CLI: proxy abstract <input.csv> [-o output.csv]"""
import argparse

from proxy.pipeline import Proxy


def main():
    parser = argparse.ArgumentParser(prog="proxy", description="Darwin Proxy: semantic redaction")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("abstract", help="abstract a CSV")
    a.add_argument("input")
    a.add_argument("-o", "--output", default="abstracted.csv")
    a.add_argument("--sample", type=int, default=5)
    args = parser.parse_args()

    if args.command == "abstract":
        proxy = Proxy()
        manifest, rows, out_rows = proxy.abstract_csv(args.input, args.output)
        _print_report(manifest, rows, out_rows, args.sample)


def _print_report(manifest, rows, out_rows, sample):
    print("=" * 78)
    print("DARWIN PROXY - Semantic Abstraction Complete")
    print("=" * 78)
    print(f"Records:    {manifest.records}")
    print(f"Abstracted: {', '.join(manifest.fields_abstracted)}")
    print(f"Preserved:  {', '.join(manifest.fields_preserved)}")
    print(f"Before:     {manifest.before_hash[:16]}...")
    print(f"After:      {manifest.after_hash[:16]}...")
    show = ["First Name", "Last Name", "Email", "State", "City", "Business Name"]
    show = [s for s in show if rows and s in rows[0]]
    print(f"\nSAMPLE TRANSFORM (first {sample}):")
    print("-" * 78)
    for i in range(min(sample, len(rows))):
        rid = rows[i].get("Stockholder ID", f"row {i}")
        print(f"\n  {rid}:")
        for field in show:
            print(f"    {field:14s} {rows[i][field]:28s} -> {out_rows[i][field]}")
    print(f"\nOutput: {manifest.before_hash[:8]} -> {manifest.after_hash[:8]}")


if __name__ == "__main__":
    main()
