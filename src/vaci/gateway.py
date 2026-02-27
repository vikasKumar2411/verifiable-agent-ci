# src/vaci/gateway.py
from __future__ import annotations

import base64
import json
import os
import shlex
import hashlib
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from vaci.crypto import (
    generate_ed25519_keypair,
    sign_obj_ed25519,
    verify_obj_ed25519,
    hashref_sha256_from_obj,
)
from vaci.schema import Signature


def _derive_key_id_from_pubkey(pub: bytes) -> str:
    """
    Derive a stable key identifier from the public key.
    IMPORTANT: must match the CLI/trust store convention:
    key_id = sha256(pubkey_raw).hexdigest()
    """
    return hashlib.sha256(pub).hexdigest()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _sha256_bytes(data: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(data).digest()


# ---------------- Manifest helpers ----------------

def sign_manifest(privkey: bytes, manifest_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns a manifest object with:
      - manifest_hash (HashRef)
      - signature (Signature)

    Signature is over Variant-B payload:
      payload = manifest_payload (no signature fields included).
    """
    href, sig = sign_obj_ed25519(privkey, manifest_payload)
    return {
        **manifest_payload,
        "manifest_hash": href.model_dump(),
        "signature": sig.model_dump(),
    }


def verify_manifest(pubkey: bytes, manifest_json: Dict[str, Any]) -> bool:
    """
    Verify manifest signature (Variant-B):
      signature over payload without signature+manifest_hash.
    """
    sigj = manifest_json.get("signature")
    if not isinstance(sigj, dict):
        return False

    payload = dict(manifest_json)
    payload.pop("signature", None)
    payload.pop("manifest_hash", None)

    try:
        sig = Signature(**sigj)
    except Exception:
        return False

    if not verify_obj_ed25519(pubkey, payload, sig):
        return False

    mh = manifest_json.get("manifest_hash")
    if isinstance(mh, dict):
        href, _ = hashref_sha256_from_obj(payload)
        if mh.get("alg") != href.alg or mh.get("hex") != href.hex or mh.get("size_bytes") != href.size_bytes:
            return False

    return True


# ---------------- Receipt ----------------

@dataclass(frozen=True)
class Receipt:
    """
    A signed, verifiable record that a command executed OR was denied by policy.

    V2 additions:
      - policy_sha256 (optional policy binding)
      - policy_decision: "allow" | "deny"
      - deny_reason: optional string
    """
    run_id: str
    policy_id: str
    call_id: str
    command: List[str]
    cwd: str
    started_at_ms: int
    finished_at_ms: int
    exit_code: int
    stdout_b64: str
    stderr_b64: str
    stdout_sha256_b64: str
    stderr_sha256_b64: str

    # V2 optional fields (only meaningful when policy-path supplied)
    policy_sha256: Optional[str] = None
    policy_decision: Optional[str] = None  # "allow" | "deny"
    deny_reason: Optional[str] = None

    signature: Signature = None  # type: ignore[assignment]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "policy_id": self.policy_id,
            "call_id": self.call_id,
            "command": self.command,
            "cwd": self.cwd,
            "started_at_ms": self.started_at_ms,
            "finished_at_ms": self.finished_at_ms,
            "exit_code": self.exit_code,
            "stdout_b64": self.stdout_b64,
            "stderr_b64": self.stderr_b64,
            "stdout_sha256_b64": self.stdout_sha256_b64,
            "stderr_sha256_b64": self.stderr_sha256_b64,

            # V2 fields (may be None)
            "policy_sha256": self.policy_sha256,
            "policy_decision": self.policy_decision,
            "deny_reason": self.deny_reason,

            "signature": self.signature.model_dump(),
        }


# ---------------- Gateway ----------------

class LocalGateway:
    """
    Minimal tool execution gateway:
    - runs a command (if allowed)
    - captures stdout/stderr/exit code
    - signs a canonical receipt payload
    """

    def __init__(self, private_key: bytes, public_key: bytes, key_id: Optional[str] = None):
        self._priv = private_key
        self._pub = public_key
        self._key_id = key_id  # optional override to stabilize key_id in Signature

    @classmethod
    def ephemeral(cls) -> "LocalGateway":
        priv, pub = generate_ed25519_keypair()
        return cls(priv, pub)

    @classmethod
    def from_keyfile(cls, path: str | Path) -> "LocalGateway":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Gateway keyfile not found: {p}")

        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Invalid gateway keyfile: expected JSON object")

        priv_b64 = data.get("privkey_b64")
        pub_b64 = data.get("pubkey_b64")
        if not isinstance(priv_b64, str) or not isinstance(pub_b64, str):
            raise ValueError("Invalid gateway keyfile: expected privkey_b64 and pubkey_b64 strings")

        priv = base64.urlsafe_b64decode(priv_b64 + "==")
        pub = base64.urlsafe_b64decode(pub_b64 + "==")

        key_id = data.get("key_id")
        if key_id is not None and not isinstance(key_id, str):
            raise ValueError("Invalid gateway keyfile: key_id must be a string if present")

        # Ensure key_id (if present) matches a deterministic derivation from pubkey.
        # Mismatched key_id values can cause signature verification failures depending
        # on verifier expectations. Prefer the derived value.
        derived = _derive_key_id_from_pubkey(pub)
        if key_id is None or key_id != derived:
            key_id = derived

        return cls(priv, pub, key_id=key_id)

    @property
    def public_key(self) -> bytes:
        return self._pub

    @property
    def private_key_bytes(self) -> bytes:
        return self._priv

    def _make_signed_receipt(
        self,
        *,
        run_id: str,
        policy_id: str,
        call_id: str,
        command_list: List[str],
        cwd: str,
        started_at_ms: int,
        finished_at_ms: int,
        exit_code: int,
        stdout: bytes,
        stderr: bytes,
        policy_sha256: Optional[str],
        policy_decision: Optional[str],
        deny_reason: Optional[str],
    ) -> Receipt:
        stdout = stdout or b""
        stderr = stderr or b""
        stdout_h = _sha256_bytes(stdout)
        stderr_h = _sha256_bytes(stderr)

        payload: Dict[str, Any] = {
            "run_id": run_id,
            "policy_id": policy_id,
            "call_id": call_id,
            "command": command_list,
            "cwd": cwd,
            "started_at_ms": started_at_ms,
            "finished_at_ms": finished_at_ms,
            "exit_code": int(exit_code),
            "stdout_sha256_b64": _b64(stdout_h),
            "stderr_sha256_b64": _b64(stderr_h),
        }

        # V2: only include these keys if a policy_sha256 is present OR decision provided.
        # This keeps signatures compatible with old tests when policy isn't used.
        if policy_sha256 is not None:
            payload["policy_sha256"] = policy_sha256
            payload["policy_decision"] = policy_decision
            payload["deny_reason"] = deny_reason
        elif policy_decision is not None:
            payload["policy_decision"] = policy_decision
            payload["deny_reason"] = deny_reason

        _, sig = sign_obj_ed25519(self._priv, payload)

        # IMPORTANT:
        # Do not override the signature's key_id after signing. Some verifiers may
        # bind key_id to the signing key (e.g., derived from the public key). If
        # key_id needs to be stable, ensure it is correctly derived at keyfile
        # load time (see from_keyfile), not mutated post-signature.


        return Receipt(
            run_id=run_id,
            policy_id=policy_id,
            call_id=call_id,
            command=command_list,
            cwd=cwd,
            started_at_ms=started_at_ms,
            finished_at_ms=finished_at_ms,
            exit_code=int(exit_code),
            stdout_b64=_b64(stdout),
            stderr_b64=_b64(stderr),
            stdout_sha256_b64=_b64(stdout_h),
            stderr_sha256_b64=_b64(stderr_h),
            policy_sha256=policy_sha256,
            policy_decision=policy_decision,
            deny_reason=deny_reason,
            signature=sig,
        )

    def run(
        self,
        command: List[str] | str,
        *,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: Optional[float] = None,
        run_id: Optional[str] = None,
        policy_id: Optional[str] = None,
        call_id: Optional[str] = None,
        policy_sha256: Optional[str] = None,
    ) -> Receipt:
        if isinstance(command, str):
            command_list = shlex.split(command)
        else:
            command_list = command

        if not command_list:
            raise ValueError("command must be non-empty")

        cwd = cwd or os.getcwd()
        started = int(time.time() * 1000)

        p = subprocess.run(
            command_list,
            cwd=cwd,
            env=env,
            timeout=timeout_s,
            capture_output=True,
            text=False,
        )

        finished = int(time.time() * 1000)

        import uuid

        run_id = run_id or uuid.uuid4().hex
        call_id = call_id or uuid.uuid4().hex
        policy_id = policy_id or "dev"

        # If policy_sha256 is present, we emit policy_decision="allow" (V2)
        policy_decision = "allow" if policy_sha256 is not None else None

        return self._make_signed_receipt(
            run_id=run_id,
            policy_id=policy_id,
            call_id=call_id,
            command_list=command_list,
            cwd=cwd,
            started_at_ms=started,
            finished_at_ms=finished,
            exit_code=int(p.returncode),
            stdout=p.stdout or b"",
            stderr=p.stderr or b"",
            policy_sha256=policy_sha256,
            policy_decision=policy_decision,
            deny_reason=None,
        )

    def run_denied(
        self,
        command: List[str] | str,
        *,
        cwd: Optional[str] = None,
        run_id: Optional[str] = None,
        policy_id: Optional[str] = None,
        call_id: Optional[str] = None,
        policy_sha256: Optional[str] = None,
        deny_reason: str,
    ) -> Receipt:
        """
        Produce a signed denial receipt WITHOUT executing subprocess.
        Exit code convention: 126 (command invoked cannot execute / policy denied).
        """
        if isinstance(command, str):
            command_list = shlex.split(command)
        else:
            command_list = command

        if not command_list:
            raise ValueError("command must be non-empty")

        cwd = cwd or os.getcwd()
        now = int(time.time() * 1000)

        import uuid

        run_id = run_id or uuid.uuid4().hex
        call_id = call_id or uuid.uuid4().hex
        policy_id = policy_id or "dev"

        # Make denial visible in stderr while still cryptographically bound.
        stderr = f"DENIED: {deny_reason}".encode("utf-8")

        return self._make_signed_receipt(
            run_id=run_id,
            policy_id=policy_id,
            call_id=call_id,
            command_list=command_list,
            cwd=cwd,
            started_at_ms=now,
            finished_at_ms=now,
            exit_code=126,
            stdout=b"",
            stderr=stderr,
            policy_sha256=policy_sha256,
            policy_decision="deny" if policy_sha256 is not None else "deny",
            deny_reason=deny_reason,
        )


# ---------------- Verification ----------------

def verify_receipt(pubkey: bytes, r: Receipt) -> bool:
    """
    Verify:
      1) stdout/stderr match their declared hashes
      2) signature matches the receipt payload

    Backward compatible:
      - Try V2 payload (includes policy_* keys when present)
      - If that fails, try V1 payload (no policy_* keys)
    """
    stdout = base64.urlsafe_b64decode(r.stdout_b64 + "==")
    stderr = base64.urlsafe_b64decode(r.stderr_b64 + "==")
    if _b64(_sha256_bytes(stdout)) != r.stdout_sha256_b64:
        return False
    if _b64(_sha256_bytes(stderr)) != r.stderr_sha256_b64:
        return False

    # V2 attempt (only if those fields were actually present when signed)
    payload_v2: Dict[str, Any] = {
        "run_id": r.run_id,
        "policy_id": r.policy_id,
        "call_id": r.call_id,
        "command": r.command,
        "cwd": r.cwd,
        "started_at_ms": r.started_at_ms,
        "finished_at_ms": r.finished_at_ms,
        "exit_code": r.exit_code,
        "stdout_sha256_b64": r.stdout_sha256_b64,
        "stderr_sha256_b64": r.stderr_sha256_b64,
    }

    has_v2 = (r.policy_sha256 is not None) or (r.policy_decision is not None) or (r.deny_reason is not None)
    if has_v2:
        payload_v2["policy_sha256"] = r.policy_sha256
        payload_v2["policy_decision"] = r.policy_decision
        payload_v2["deny_reason"] = r.deny_reason
        if verify_obj_ed25519(pubkey, payload_v2, r.signature):
            return True

    # V1 fallback (no policy_* keys)
    payload_v1 = {
        "run_id": r.run_id,
        "policy_id": r.policy_id,
        "call_id": r.call_id,
        "command": r.command,
        "cwd": r.cwd,
        "started_at_ms": r.started_at_ms,
        "finished_at_ms": r.finished_at_ms,
        "exit_code": r.exit_code,
        "stdout_sha256_b64": r.stdout_sha256_b64,
        "stderr_sha256_b64": r.stderr_sha256_b64,
    }
    return verify_obj_ed25519(pubkey, payload_v1, r.signature)