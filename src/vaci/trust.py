from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Set


class TrustError(Exception):
    pass


@dataclass(frozen=True)
class TrustStore:
    trusted_key_ids: Set[str]

    @staticmethod
    def load(path: str | Path) -> "TrustStore":
        p = Path(path)
        if not p.exists():
            raise TrustError(f"Trust store not found: {p}")

        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            raise TrustError(f"Failed to parse trust store JSON: {p}: {e}") from e

        if not isinstance(data, dict):
            raise TrustError("Trust store must be a JSON object")

        ids = data.get("trusted_key_ids", [])
        if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
            raise TrustError('Trust store field "trusted_key_ids" must be a list[str]')

        return TrustStore(trusted_key_ids=set(ids))

    def is_trusted(self, key_id: str) -> bool:
        return key_id in self.trusted_key_ids


def key_id_from_pubkey_raw(pubkey_raw: bytes) -> str:
    # sha256(pubkey_raw) hex digest is a stable, audit-friendly key_id
    return hashlib.sha256(pubkey_raw).hexdigest()


def key_id_from_receipt_json(receipt_json: Dict[str, Any], pubkey_raw: bytes) -> str:
    """
    Prefer receipt.signature.key_id if present; otherwise derive from pubkey.
    """
    sig = receipt_json.get("signature", {})
    if isinstance(sig, dict):
        kid = sig.get("key_id") or sig.get("keyId")
        if isinstance(kid, str) and kid.strip():
            return kid.strip()

    # fallback: derive key_id from pubkey (works even if signature doesn't store key_id)
    return key_id_from_pubkey_raw(pubkey_raw)


def assert_trusted_signer(*, key_id: str, trust_path: str | Path) -> None:
    store = TrustStore.load(trust_path)
    if not store.is_trusted(key_id):
        raise TrustError(f"Untrusted signer key_id: {key_id}")