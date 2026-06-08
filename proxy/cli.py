"""Darwin Proxy CLI (v2), on the Proxy orchestrator.

  proxy abstract <input> [-o out.csv] [--k N] [--mode oneway|map|encrypt]
        [--lang en] [--qi col,col] [--key PEM] [--no-sign]
        [--map-path P] [--map-secret-env VAR] [--ttl S]
  proxy verify <manifest.json> [--output out.csv] [--darwin-root HEX]
  proxy reverse <input.csv> -o <out.csv> --manifest <m.json>
        --map <map.enc> [--secret-env VAR]
  proxy serve [--host H] [--port N]
"""
import argparse
import json
import os

from proxy.cert import DEFAULT_KEY_PATH, load_or_create_key, verify_manifest
from proxy.certify import recheck
from proxy.ingest import read
from proxy.schemas_v2 import AbstractionManifestV2

MAP_SECRET_DEFAULT = "PROXY_MAP_SECRET"


def _build_proxy(args):
    """Construct the orchestrator. Isolated so tests can inject a model-free engine."""
    from proxy.orchestrator import Proxy
    key = None if getattr(args, "no_sign", False) else load_or_create_key(getattr(args, "key", DEFAULT_KEY_PATH))
    ner = not (getattr(args, "no_ner", False) or getattr(args, "fast", False))
    return Proxy(language=getattr(args, "lang", "en"), k_threshold=getattr(args, "k", 5),
                 round_trip=(getattr(args, "mode", "oneway") == "map"), signing_key=key,
                 ner=ner, model=getattr(args, "model", None),
                 batch_size=getattr(args, "batch_size", 32),
                 sample_size=getattr(args, "sample_size", None))


def main(argv=None):
    p = argparse.ArgumentParser(prog="proxy", description="Darwin Proxy: semantic redaction")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("abstract", help="abstract a file and write a signed certificate")
    a.add_argument("input")
    a.add_argument("-o", "--output", default="abstracted.csv")
    a.add_argument("--k", type=int, default=5)
    a.add_argument("--mode", choices=["oneway", "map", "encrypt"], default="oneway")
    a.add_argument("--lang", default="en")
    a.add_argument("--qi", default=None, help="comma-separated columns to force as quasi-identifiers")
    a.add_argument("--key", default=DEFAULT_KEY_PATH)
    a.add_argument("--no-sign", action="store_true")
    a.add_argument("--map-path", default=None)
    a.add_argument("--map-secret-env", default=MAP_SECRET_DEFAULT)
    a.add_argument("--ttl", type=int, default=None)
    a.add_argument("--fast", action="store_true", help="pattern-only, no NER (fastest; skips name/org/location)")
    a.add_argument("--no-ner", action="store_true", help="alias for --fast")
    a.add_argument("--model", default=None, help="spaCy model, e.g. en_core_web_sm for speed")
    a.add_argument("--batch-size", type=int, default=32)
    a.add_argument("--sample-size", type=int, default=None,
                   help="type columns from a sample of N rows (large homogeneous data; may miss sparse PII)")

    v = sub.add_parser("verify", help="re-check a certificate")
    v.add_argument("manifest")
    v.add_argument("--output", default=None, help="output artifact to recompute hash/k against")
    v.add_argument("--darwin-root", default=None)

    r = sub.add_parser("reverse", help="reverse substituted identifiers using an encrypted map")
    r.add_argument("input")
    r.add_argument("-o", "--output", default="reversed.csv")
    r.add_argument("--manifest", required=True)
    r.add_argument("--map", required=True)
    r.add_argument("--secret-env", default=MAP_SECRET_DEFAULT)

    sv = sub.add_parser("serve", help="run the HTTP service")
    sv.add_argument("--host", default="0.0.0.0")
    sv.add_argument("--port", type=int, default=8000)

    args = p.parse_args(argv)
    return {"abstract": _abstract, "verify": _verify,
            "reverse": _reverse, "serve": _serve}[args.command](args)


def _abstract(args):
    if args.mode == "map" and not os.environ.get(args.map_secret_env):
        raise SystemExit(f"--mode map requires the map secret in ${args.map_secret_env}")
    qi_config = None
    if args.qi:
        from proxy.gate import _band, _identity, _suppress
        qi_config = {c: [_identity, _band(10000), _suppress] for c in args.qi.split(",")}
    proxy = _build_proxy(args)
    out_path, manifest = proxy.abstract_file(
        args.input, args.output, reversibility=args.mode, qi_config=qi_config,
        sign=not args.no_sign)
    if args.mode == "map":
        map_path = args.map_path or (args.output + ".map.enc")
        proxy.transformer.save_map(map_path, os.environ[args.map_secret_env], args.ttl)
        print(f"map:        {map_path} (encrypted, round-trip)")
    _report(manifest, out_path)
    return 0


def _verify(args):
    with open(args.manifest) as f:
        manifest = AbstractionManifestV2.model_validate_json(f.read())
    if args.output:
        rep = recheck(manifest, read(args.output), darwin_root=args.darwin_root)
        sig, ka = rep["signature"], rep["k_anonymity"]
    else:
        sig = verify_manifest(manifest, darwin_root=args.darwin_root)
        ka = None
    root_label = {"darwin": "Darwin-certified (authority root)",
                  "self": "Self-signed (OSS self-attestation)",
                  "none": "unverified"}[sig["root"]]
    print("=" * 78)
    print("DARWIN PROXY - Certificate Verification")
    print("=" * 78)
    print(f"doc_id:     {manifest.doc_id}")
    print(f"signature:  {'VALID' if sig['valid'] else 'INVALID'}")
    print(f"trust root: {root_label}")
    print(f"records:    {manifest.records}")
    print(f"reversible: {manifest.reversibility}")
    if ka is not None:
        if ka.get("assessed"):
            print(f"k-anonymity: recomputed k={ka['recomputed_k']} (threshold {ka['threshold']}) "
                  f"[{'CERTIFIED' if ka['certified'] else 'FAILED'}]")
        else:
            print(f"k-anonymity: NOT ASSESSED ({ka.get('reason')})")
    raise SystemExit(0 if sig["valid"] else 1)


def _reverse(args):
    from proxy.maps import MapStore, fernet_from_secret
    from proxy.transform import Transformer
    secret = os.environ.get(args.secret_env)
    if not secret:
        raise SystemExit(f"map secret not found in ${args.secret_env}")
    with open(args.manifest) as f:
        manifest = AbstractionManifestV2.model_validate_json(f.read())
    tr = Transformer(round_trip=True)
    tr.substitutor.store = MapStore.load(args.map, fernet_from_secret(secret))
    restored = tr.reverse_table(read(args.input), manifest.detection)
    restored.df.to_csv(args.output, index=False)
    print(f"reversed -> {args.output}")
    return 0


def _serve(args):
    import uvicorn
    uvicorn.run("proxy.service:app", host=args.host, port=args.port)


def _report(manifest, out_path):
    g = manifest.gate or {}
    print("=" * 78)
    print("DARWIN PROXY - Semantic Abstraction Complete")
    print("=" * 78)
    print(f"records:    {manifest.records}")
    print(f"detected:   {manifest.detection}")
    print(f"operators:  {manifest.operators}")
    print(f"kept:       {', '.join(manifest.kept_columns)}")
    print(f"reversible: {manifest.reversibility}")
    if g.get("assessed"):
        print(f"re-id gate: k={g.get('k')} (threshold {g.get('threshold')}) "
              f"[{'PASS' if g.get('passed') else 'FAIL'}]")
    else:
        print(f"re-id gate: NOT ASSESSED ({g.get('reason')})")
    if manifest.signature:
        print(f"signed:     self ({manifest.signer_pubkey[:16]}...)")
    print(f"output:     {out_path}")
    print(f"cert:       {out_path}.manifest.json")


if __name__ == "__main__":
    main()
