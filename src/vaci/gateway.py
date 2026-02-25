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


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _sha256_bytes(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(data).digest()


@dataclass(frozen=True)
class Receipt:
    """
    A signed, verifiable record that a command actually executed.
    """
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

    @property
    def public_key(self) -> bytes:
        return self._pub

    def run(
        self,
        command: List[str] | str,
        *,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: Optional[float] = None,
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
            # IMPORTANT: payload includes hashes, not just raw output,
            # so consumers can verify integrity cheaply.
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
        "command": r.command,
        "cwd": r.cwd,
        "started_at_ms": r.started_at_ms,
        "finished_at_ms": r.finished_at_ms,
        "exit_code": r.exit_code,
        "stdout_sha256_b64": r.stdout_sha256_b64,
        "stderr_sha256_b64": r.stderr_sha256_b64,
    }
    return verify_obj_ed25519(pubkey, payload, r.signature)