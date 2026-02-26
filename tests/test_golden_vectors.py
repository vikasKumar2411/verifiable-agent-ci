from __future__ import annotations

import base64
import json
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from vaci.crypto import hashref_sha256_from_obj, verify_obj_ed25519
from vaci.schema import Signature


FIXTURE = Path(__file__).parent / "fixtures" / "golden_manifest.json"


def _b64url_decode_nopad(s: str) -> bytes:
    # urlsafe b64 without padding
    return base64.urlsafe_b64decode(s + "==")


def test_golden_manifest_hash_and_signature_vector():
    fx = json.loads(FIXTURE.read_text(encoding="utf-8"))
    key = fx["key"]
    signed = fx["signed_manifest"]

    pub_raw = _b64url_decode_nopad(key["pubkey_b64"])
    pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)

    # key_id must be sha256(raw_pubkey)
    expected_kid = hashlib.sha256(pub_raw).hexdigest()
    assert key["key_id"] == expected_kid

    declared_href = signed["manifest_hash"]
    declared_hex = declared_href["hex"]
    declared_size = declared_href["size_bytes"]

    sig_obj = signed["signature"]
    sig = Signature(**sig_obj)

    # Variant A: remove only signature (includes manifest_hash)
    payload_a = dict(signed)
    payload_a.pop("signature", None)

    # Variant B: remove signature and manifest_hash (recommended signer behavior)
    payload_b = dict(signed)
    payload_b.pop("signature", None)
    payload_b.pop("manifest_hash", None)

    href_a, _ = hashref_sha256_from_obj(payload_a)
    href_b, _ = hashref_sha256_from_obj(payload_b)

    def _href_matches(href) -> bool:
        return href.hex == declared_hex and href.size_bytes == declared_size

    assert _href_matches(href_b), "golden vector must be Variant-B"
    assert not _href_matches(href_a), "golden vector must NOT be Variant-A"
    assert not _href_matches(href_a), "golden vector should not rely on self-hashing Variant-A"

    # Signature must verify over the payload variant that matches the declared hash.
    assert verify_obj_ed25519(pub, payload_b, sig)