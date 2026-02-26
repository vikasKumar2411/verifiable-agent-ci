from __future__ import annotations

import base64
import json
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from vaci.schema import HashRef, Signature
from cryptography.hazmat.primitives.asymmetric import ed25519


def _privkey_obj(priv: ed25519.Ed25519PrivateKey | bytes) -> ed25519.Ed25519PrivateKey:
    if isinstance(priv, (bytes, bytearray)):
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(priv))
    return priv

def _pubkey_obj(pub: ed25519.Ed25519PublicKey | bytes) -> ed25519.Ed25519PublicKey:
    if isinstance(pub, (bytes, bytearray)):
        return ed25519.Ed25519PublicKey.from_public_bytes(bytes(pub))
    return pub

# ----------------------------
# Canonicalization + hashing
# ----------------------------

def canonical_json_bytes(obj: Any) -> bytes:
    """
    Deterministic JSON encoding:
    - sorted keys
    - no whitespace
    - UTF-8
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> Tuple[str, int]:
    h = hashlib.sha256(data).hexdigest()
    return h, len(data)


def hashref_sha256_from_bytes(data: bytes) -> HashRef:
    hex_digest, size = sha256_bytes(data)
    return HashRef(alg="sha256", hex=hex_digest, size_bytes=size)


def hashref_sha256_from_obj(obj: Any) -> Tuple[HashRef, bytes]:
    b = canonical_json_bytes(obj)
    return hashref_sha256_from_bytes(b), b


# ----------------------------
# Key handling
# ----------------------------

def generate_ed25519_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def public_key_id(pub: Ed25519PublicKey) -> str:
    """
    Stable key identifier = sha256(raw_pubkey_bytes).
    """
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def export_private_key_pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def export_public_key_pem(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(pem: bytes) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key_pem(pem: bytes) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem)


# ----------------------------
# Signing + verification
# ----------------------------

def sign_payload_bytes_ed25519(priv: Ed25519PrivateKey, payload: bytes) -> str:
    sig = priv.sign(payload)
    return base64.b64encode(sig).decode("ascii")


def verify_payload_bytes_ed25519(pub: Ed25519PublicKey, payload: bytes, sig_b64: str) -> bool:
    try:
        sig = base64.b64decode(sig_b64.encode("ascii"))
        pub.verify(sig, payload)
        return True
    except Exception:
        return False


def sign_obj_ed25519(priv: Ed25519PrivateKey, obj: Any) -> Tuple[HashRef, Signature]:
    """
    Returns:
      - HashRef of canonical payload bytes
      - Signature over canonical payload bytes
    """
    href, payload = hashref_sha256_from_obj(obj)
    priv = _privkey_obj(priv)
    pub = priv.public_key()
    kid = public_key_id(pub)
    sig_b64 = sign_payload_bytes_ed25519(priv, payload)
    sig = Signature(alg="ed25519", key_id=kid, sig_b64=sig_b64)
    return href, sig


def verify_obj_ed25519(pub: Ed25519PublicKey, obj: Any, signature: Signature) -> bool:
    if signature.alg != "ed25519":
        return False
    href, payload = hashref_sha256_from_obj(obj)
    # Optional consistency check: key_id should match provided pubkey
    if signature.key_id != public_key_id(pub):
        return False
    return verify_payload_bytes_ed25519(pub, payload, signature.sig_b64)


# ----------------------------
# Convenience: sign "receipt payload"
# ----------------------------

@dataclass(frozen=True)
class SignedPayload:
    payload_hash: HashRef
    signature: Signature
    canonical_bytes: bytes


def sign_obj_ed25519_with_bytes(priv: Ed25519PrivateKey, obj: Any) -> SignedPayload:
    href, payload = hashref_sha256_from_obj(obj)
    priv = _privkey_obj(priv)
    pub = priv.public_key()
    kid = public_key_id(pub)
    sig_b64 = sign_payload_bytes_ed25519(priv, payload)
    sig = Signature(alg="ed25519", key_id=kid, sig_b64=sig_b64)
    return SignedPayload(payload_hash=href, signature=sig, canonical_bytes=payload)