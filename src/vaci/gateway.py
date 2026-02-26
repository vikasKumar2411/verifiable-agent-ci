from __future__ import annotations

import base64
import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from vaci.crypto import sign_obj_ed25519, verify_obj_ed25519, generate_ed25519_keypair
from vaci.schema import Signature
import json
from pathlib import Path
from vaci.crypto import sign_obj_ed25519, verify_obj_ed25519

def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _sha256_bytes(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(data).digest()


def sign_manifest(privkey: bytes, manifest_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns a manifest object with:
      - manifest_hash (HashRef)
      - signature (Signature)
    The signature is over the *payload only* (no signature fields included).
    """
    href, sig = sign_obj_ed25519(privkey, manifest_payload)
    return {
        **manifest_payload,
        "manifest_hash": href.model_dump(),
        "signature": sig.model_dump(),
    }


def verify_manifest(pubkey: bytes, manifest_json: Dict[str, Any]) -> bool:
    """
    Verify manifest signature (and optional hash consistency).
    """
    sigj = manifest_json.get("signature")
    if not isinstance(sigj, dict):
        return False

    # payload = manifest without signature fields
    payload = dict(manifest_json)
    payload.pop("signature", None)
    payload.pop("manifest_hash", None)

    sig = Signature(**sigj)

    ok = verify_obj_ed25519(pubkey, payload, sig)
    if not ok:
        return False

    # optional: if manifest_hash exists, ensure it matches payload
    mh = manifest_json.get("manifest_hash")
    if isinstance(mh, dict):
        from vaci.crypto import hashref_sha256_from_obj
        href, _ = hashref_sha256_from_obj(payload)
        if mh.get("alg") != href.alg or mh.get("hex") != href.hex or mh.get("size_bytes") != href.size_bytes:
            return False

    return True

@dataclass(frozen=True)
class Receipt:
    """
    A signed, verifiable record that a command actually executed.
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
    signature: Signature

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
            "signature": self.signature.model_dump(),
        }


class LocalGateway:
    """
    Minimal 'tool execution gateway' for MVP:
    - runs a command
    - captures stdout/stderr/exit code
    - signs a canonical receipt payload
    """

    def __init__(self, private_key: bytes, public_key: bytes, key_id: Optional[str] = None):
        self._priv = private_key
        self._pub = public_key
        self._key_id = key_id  # optional override

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

        return cls(priv, pub, key_id=key_id)

    @property
    def public_key(self) -> bytes:
        return self._pub

    @property
    def private_key_bytes(self) -> bytes:
        return self._priv

    def run(
        self,
        command: List[str] | str,
        *,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: Optional[float] = None,
        run_id: str,
        policy_id: str,
        call_id: str,
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

        stdout = p.stdout or b""
        stderr = p.stderr or b""
        stdout_h = _sha256_bytes(stdout)
        stderr_h = _sha256_bytes(stderr)

        payload = {
            "run_id": run_id,
            "policy_id": policy_id,
            "call_id": call_id,
            "command": command_list,
            "cwd": cwd,
            "started_at_ms": started,
            "finished_at_ms": finished,
            "exit_code": int(p.returncode),
            "stdout_sha256_b64": _b64(stdout_h),
            "stderr_sha256_b64": _b64(stderr_h),
        }

        href, sig = sign_obj_ed25519(self._priv, payload)

        # allow key_id override if you want stable IDs later
        if self._key_id:
            sig = Signature(**{**sig.model_dump(), "key_id": self._key_id})

        return Receipt(
            run_id=run_id,
            policy_id=policy_id,
            call_id=call_id,
            command=command_list,
            cwd=cwd,
            started_at_ms=started,
            finished_at_ms=finished,
            exit_code=int(p.returncode),
            stdout_b64=_b64(stdout),
            stderr_b64=_b64(stderr),
            stdout_sha256_b64=_b64(stdout_h),
            stderr_sha256_b64=_b64(stderr_h),
            signature=sig,
        )


def verify_receipt(pubkey: bytes, r: Receipt) -> bool:
    """
    Verify:
    1) signature matches the receipt payload
    2) stdout/stderr match their declared hashes
    """
    # 1) validate output hashes
    stdout = base64.urlsafe_b64decode(r.stdout_b64 + "==")
    stderr = base64.urlsafe_b64decode(r.stderr_b64 + "==")
    if _b64(_sha256_bytes(stdout)) != r.stdout_sha256_b64:
        return False
    if _b64(_sha256_bytes(stderr)) != r.stderr_sha256_b64:
        return False

    # 2) verify signature over canonical payload (same as gateway signs)
    payload = {
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
    return verify_obj_ed25519(pubkey, payload, r.signature)