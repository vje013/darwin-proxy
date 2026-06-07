"""Certificate signing and the trust-root split.

The signed manifest IS the certificate. Signing is Ed25519 over a canonical
serialization of the manifest with the signature fields excluded, so the
signature binds every other field (hashes, gate result, policy, redactions).

Two roots, one verifier:
  - Self-signed (OSS): the engine signs with a local key it generates and keeps.
    Anyone can verify integrity, but the root is the operator's own key, i.e. a
    self-attestation: "this run produced this output, untampered."
  - Darwin-certified (authority): a manifest whose signer public key equals the
    Darwin authority root. Only Darwin / DAC holds that private key, so only
    Darwin can issue an authority-rooted certificate. This is the stamp.

`verify_manifest` reports which root signed: 'darwin', 'self', or 'none'. The
engine gives away the test rig (self-sign, free); Darwin owns the stamp.
"""
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

# The Darwin authority root (Ed25519 public key, raw hex). Set to the DAC root.
# Empty by default in OSS: no authority root is configured, so nothing verifies
# as Darwin-certified until this is set to the real DAC signing root.
DARWIN_ROOT_PUBKEY = os.environ.get("PROXY_DARWIN_ROOT", "")

DEFAULT_KEY_PATH = os.path.expanduser("~/.darwin-proxy/signing_key.pem")


def canonical_message(manifest):
    """Deterministic bytes to sign: manifest minus the signature fields."""
    data = manifest.model_dump(mode="json", exclude={"signature", "signer_pubkey"})
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_key():
    return Ed25519PrivateKey.generate()


def load_or_create_key(path=DEFAULT_KEY_PATH):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = generate_key()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)
    os.chmod(path, 0o600)
    return key


def _pubkey_hex(private_key):
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def sign_manifest(manifest, private_key):
    """Sign in place: sets signature (hex) and signer_pubkey (raw hex)."""
    manifest.signature = ""
    manifest.signer_pubkey = ""
    msg = canonical_message(manifest)
    manifest.signature = private_key.sign(msg).hex()
    manifest.signer_pubkey = _pubkey_hex(private_key)
    return manifest


def verify_manifest(manifest, darwin_root=None):
    """Return {valid, root, signer}. root in {'darwin','self','none'}."""
    darwin_root = (darwin_root if darwin_root is not None else DARWIN_ROOT_PUBKEY) or ""
    signer = manifest.signer_pubkey or ""
    if not manifest.signature or not signer:
        return {"valid": False, "root": "none", "signer": signer}
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer))
        pub.verify(bytes.fromhex(manifest.signature), canonical_message(manifest))
    except (InvalidSignature, ValueError):
        return {"valid": False, "root": "none", "signer": signer}
    root = "darwin" if signer == darwin_root else "self"
    return {"valid": True, "root": root, "signer": signer}
