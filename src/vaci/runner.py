# src/vaci/runner.py
from __future__ import annotations

import base64
from cryptography.hazmat.primitives import serialization
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from vaci.gateway import LocalGateway, Receipt, sign_manifest

# policy is optional, but if provided we enforce it deterministically
from vaci.core.policy import load_policy, evaluate


def _now_ms() -> int:
    return int(time.time() * 1000)


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_obj(obj: Any) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def _entry_hash(entry: Dict[str, Any]) -> str:
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    return _sha256_obj(payload)


def _manifest_payload_from_signed(mj: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(mj)
    payload.pop("signature", None)
    payload.pop("manifest_hash", None)
    return payload


def _compute_policy_sha256(policy_path: Optional[str]) -> Optional[str]:
    if not policy_path:
        return None
    p = Path(policy_path).expanduser()
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    if not p.exists():
        raise FileNotFoundError(str(p))
    return _sha256_file(p)


def _write_gateway_keyfile(path: Path, gw: LocalGateway) -> None:
    """
    Persist a gateway keyfile in the same format as vaci.cli keygen produces,
    so LocalGateway.from_keyfile() can reload it.
    """
    import base64 as _b64
    from cryptography.hazmat.primitives import serialization

    priv = getattr(gw, "private_key_bytes", None)
    pub = getattr(gw, "public_key", None)

    # Some implementations may expose these as callables/properties
    if callable(priv):
        priv = priv()
    if callable(pub):
        pub = pub()

    # ---- coerce private key to raw bytes ----
    if hasattr(priv, "private_bytes"):
        priv = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    elif isinstance(priv, str):
        # allow urlsafe b64 (no padding) just in case
        priv = _b64.urlsafe_b64decode(priv +"==")

    # ---- coerce public key to raw bytes ----
    if hasattr(pub, "public_bytes"):
        pub = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    elif isinstance(pub, str):
        pub = _b64.urlsafe_b64decode(pub  +"==")

    if not isinstance(priv, (bytes, bytearray)) or not isinstance(pub, (bytes, bytearray)):
        raise TypeError("LocalGateway must expose raw private/public key bytes (or cryptography key objects)")

    priv_b = bytes(priv)
    pub_b = bytes(pub)
    key_id = hashlib.sha256(pub_b).hexdigest()
    obj = {
        "kty": "Ed25519",
        "format": "raw",
        "privkey_b64": base64.urlsafe_b64encode(priv).decode("ascii").rstrip("="),
        "pubkey_b64": base64.urlsafe_b64encode(pub).decode("ascii").rstrip("="),
        "key_id": key_id,
    }
    _write_json(path, obj)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def _coerce_pubkey_bytes(gw: LocalGateway) -> bytes:
    """
    Return Ed25519 public key as raw bytes.
    Supports gateways that expose bytes OR cryptography key objects.
    """
    pk = getattr(gw, "public_key", None)
    if callable(pk):
        pk = pk()
    if pk is None:
        raise TypeError("LocalGateway must expose public_key")

    if hasattr(pk, "public_bytes"):
        return pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    if isinstance(pk, (bytes, bytearray)):
        return bytes(pk)
    raise TypeError(f"Unsupported public_key type: {type(pk)}")


@dataclass(frozen=True)
class RunArtifacts:
    receipt_path: Path
    pubkey_path: Path
    manifest_path: Path
    toolcall_path: Optional[Path] = None


class SafeAgentRunner:
    """
    Agent-friendly session runner that emits:
      - signed receipt_{call_id}.json
      - public_key_{call_id}.json
      - run_manifest.json (chained, signed, append-only semantics)
      - convenience latest: receipt.json + public_key_b64.json

    Pivot additions:
      - require_policy=True for “serious mode”
      - record_tool_call() writes a sidecar toolcall_<call_id>.json and binds it into the manifest entry
    """

    def __init__(
        self,
        *,
        out_dir: str | Path = ".vaci",
        run_id: Optional[str] = None,
        policy_id: str = "dev",
        policy_path: Optional[str] = None,
        keyfile: Optional[str | Path] = ".vaci_keys/gateway_ed25519.key",
        ephemeral: bool = False,
        cwd: Optional[str] = None,
        require_policy: bool = False,   # NEW
    ):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.run_id = run_id or os.environ.get("VACI_RUN_ID") or uuid.uuid4().hex
        self.policy_id = policy_id or os.environ.get("VACI_POLICY_ID") or "dev"
        self.policy_path = policy_path or os.environ.get("VACI_POLICY_PATH")
        self.cwd = cwd

        self.require_policy = bool(require_policy)
        if self.require_policy and not self.policy_path:
            raise ValueError("require_policy=True but no policy_path provided")

        # gateway selection
        self.ephemeral = bool(ephemeral)
        self.keyfile = Path(keyfile) if keyfile is not None else None

        # load policy (optional, but mandatory when require_policy=True)
        self._policy: Optional[Dict[str, Any]] = None
        if self.policy_path:
            self._policy = load_policy(self.policy_path)
        elif self.require_policy:
            raise ValueError("require_policy=True but policy could not be loaded")

        # compute policy sha (optional)
        self.policy_sha256: Optional[str] = _compute_policy_sha256(self.policy_path) if self.policy_path else None

        # construct gateway
        self.gw = self._load_gateway()

        self.manifest_path = self.out_dir / "run_manifest.json"

    def _load_gateway(self) -> LocalGateway:
        if self.ephemeral:
            # stable ephemeral per out_dir
            ephem_keyfile = self.out_dir / "ephemeral_gateway_ed25519.key"
            if ephem_keyfile.exists():
                return LocalGateway.from_keyfile(str(ephem_keyfile))
            gw = LocalGateway.ephemeral()
            _write_gateway_keyfile(ephem_keyfile, gw)
            return gw

        if not self.keyfile:
            raise ValueError("keyfile must be provided when ephemeral=False")
        return LocalGateway.from_keyfile(str(self.keyfile))

    def _policy_decide(self, command: List[str], cwd: str) -> Tuple[bool, Optional[str]]:
        if not self._policy:
            # policy optional mode: allow
            return True, None
        dec = evaluate(self._policy, command, cwd=cwd)
        if dec.allowed:
            return True, None
        return False, dec.reason

    def run(
        self,
        command: List[str],
        *,
        cwd: Optional[str] = None,
        call_id: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: Optional[float] = None,
    ) -> Tuple[Receipt, RunArtifacts]:
        """
        Execute or deny based on policy. Always emits artifacts + appends manifest.
        Returns (receipt, artifacts).
        """
        if not command:
            raise ValueError("command must be non-empty")

        call_id = call_id or uuid.uuid4().hex
        exec_cwd = cwd or self.cwd or os.getcwd()

        allowed, deny_reason = self._policy_decide(command, exec_cwd)

        if not allowed:
            receipt = self.gw.run_denied(
                command,
                cwd=exec_cwd,
                run_id=self.run_id,
                policy_id=self.policy_id,
                call_id=call_id,
                policy_sha256=self.policy_sha256,
                deny_reason=deny_reason or "policy denied",
            )
        else:
            receipt = self.gw.run(
                command,
                cwd=exec_cwd,
                env=env,
                timeout_s=timeout_s,
                run_id=self.run_id,
                policy_id=self.policy_id,
                call_id=call_id,
                policy_sha256=self.policy_sha256,
            )

        # write per-call artifacts
        receipt_name = f"receipt_{call_id}.json"
        pubkey_name = f"public_key_{call_id}.json"

        pubkey_path = self.out_dir / pubkey_name
        receipt_path = self.out_dir / receipt_name

        pubkey_bytes = _coerce_pubkey_bytes(self.gw)
        _write_json(pubkey_path, {"pubkey_b64": base64.urlsafe_b64encode(pubkey_bytes).decode("ascii").rstrip("=")})
        _write_json(receipt_path, receipt.to_dict())

        # latest convenience filenames
        _write_json(self.out_dir / "public_key_b64.json", {"pubkey_b64": base64.urlsafe_b64encode(pubkey_bytes).decode("ascii").rstrip("=")})
        _write_json(self.out_dir / "receipt.json", receipt.to_dict())

        # append manifest
        self._append_manifest_entry(
            call_id=call_id,
            receipt_path=receipt_path,
            pubkey_path=pubkey_path,
        )

        return receipt, RunArtifacts(
            receipt_path=receipt_path,
            pubkey_path=pubkey_path,
            manifest_path=self.manifest_path,
            toolcall_path=None,
        )

    def _append_manifest_entry(self, *, call_id: str, receipt_path: Path, pubkey_path: Path) -> None:
        entry: Dict[str, Any] = {
            "call_id": call_id,
            "created_at_ms": _now_ms(),
            "receipt_path": receipt_path.name,
            "receipt_sha256": _sha256_file(receipt_path),
            "pubkey_path": pubkey_path.name,
            "pubkey_sha256": _sha256_file(pubkey_path),
            "policy_sha256": self.policy_sha256,
        }

        if self.manifest_path.exists():
            mj = _read_json(self.manifest_path)
            payload = _manifest_payload_from_signed(mj)

            if payload.get("finalized") is True:
                raise RuntimeError(
                    "manifest is finalized; refusing to append\n"
                    "Hint: start a new session by:\n"
                    "  - removing the out-dir (e.g. rm -rf .vaci), or\n"
                    "  - using a different --out-dir, or\n"
                    "  - using a new run_id in a fresh directory."
                )

            if payload.get("run_id") != self.run_id:
                raise RuntimeError(f"run_id mismatch vs existing manifest ({payload.get('run_id')} != {self.run_id})")
            if payload.get("policy_id") != self.policy_id:
                raise RuntimeError(f"policy_id mismatch vs existing manifest ({payload.get('policy_id')} != {self.policy_id})")

            if payload.get("policy_sha256") != self.policy_sha256:
                raise RuntimeError("policy_sha256 mismatch vs existing manifest")

            receipts = payload.get("receipts")
            if not isinstance(receipts, list):
                raise RuntimeError("manifest payload receipts must be a list")

            prev = receipts[-1].get("entry_hash") if receipts else None
            entry["prev_entry_hash"] = prev
            entry["entry_hash"] = _entry_hash(entry)

            receipts.append(entry)
            payload["updated_at_ms"] = _now_ms()
        else:
            entry["prev_entry_hash"] = None
            entry["entry_hash"] = _entry_hash(entry)
            payload = {
                "run_id": self.run_id,
                "policy_id": self.policy_id,
                "git_sha": None,
                "created_at_ms": _now_ms(),
                "updated_at_ms": _now_ms(),
                "finalized": False,
                "policy_sha256": self.policy_sha256,
                "receipts": [entry],
            }

        signed = sign_manifest(self.gw.private_key_bytes, payload)
        _write_json(self.manifest_path, signed)

    # ------------------------
    # NEW: tool-call sidecar
    # ------------------------
    def record_tool_call(
        self,
        *,
        call_id: str,
        tool: str,
        args_json: Any,
        result_json: Any,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """
        Write toolcall_<call_id>.json and bind it into the manifest entry.

        The manifest entry gains:
          - toolcall_path
          - toolcall_sha256
          - toolcall_record_sha256  (sha256 over canonical {tool,args,result})
        """
        if not tool or not isinstance(tool, str):
            raise ValueError("tool must be a non-empty string")

        toolcall_payload: Dict[str, Any] = {
            "tool": tool,
            "args": args_json,
            "result": result_json,
            "args_sha256": _sha256_obj(args_json),
            "result_sha256": _sha256_obj(result_json),
            "toolcall_record_sha256": _sha256_obj({"tool": tool, "args": args_json, "result": result_json}),
        }
        if extra is not None:
            toolcall_payload["extra"] = extra

        toolcall_path = self.out_dir / f"toolcall_{call_id}.json"
        _write_json(toolcall_path, toolcall_payload)

        self._attach_toolcall_to_manifest(call_id=call_id, toolcall_path=toolcall_path, toolcall_record_sha=toolcall_payload["toolcall_record_sha256"])
        return toolcall_path

    def _attach_toolcall_to_manifest(self, *, call_id: str, toolcall_path: Path, toolcall_record_sha: str) -> None:
        if not self.manifest_path.exists():
            raise FileNotFoundError(str(self.manifest_path))

        mj = _read_json(self.manifest_path)
        payload = _manifest_payload_from_signed(mj)

        if payload.get("finalized") is True:
            raise RuntimeError("manifest is finalized; refusing to attach toolcall")

        receipts = payload.get("receipts")
        if not isinstance(receipts, list) or not receipts:
            raise RuntimeError("manifest missing receipts list")

        # locate entry
        idx = None
        for i, e in enumerate(receipts):
            if isinstance(e, dict) and e.get("call_id") == call_id:
                idx = i
                break
        if idx is None:
            raise RuntimeError(f"call_id not found in manifest: {call_id}")

        # mutate entry: add toolcall refs
        new_entry = dict(receipts[idx])
        new_entry["toolcall_path"] = toolcall_path.name
        new_entry["toolcall_sha256"] = _sha256_file(toolcall_path)
        new_entry["toolcall_record_sha256"] = toolcall_record_sha

        # IMPORTANT: entry mutated => re-hash forward to keep chain consistent
        prev_hash = receipts[idx - 1].get("entry_hash") if idx > 0 else None
        for j in range(idx, len(receipts)):
            cur = dict(receipts[j])
            if j == idx:
                cur = new_entry

            cur["prev_entry_hash"] = prev_hash
            cur["entry_hash"] = _entry_hash(cur)
            receipts[j] = cur
            prev_hash = cur["entry_hash"]

        payload["receipts"] = receipts
        payload["updated_at_ms"] = _now_ms()

        signed = sign_manifest(self.gw.private_key_bytes, payload)
        _write_json(self.manifest_path, signed)

    def finalize(self) -> Path:
        """
        Finalize (lock) the session manifest and re-sign.
        """
        if not self.manifest_path.exists():
            raise FileNotFoundError(str(self.manifest_path))

        mj = _read_json(self.manifest_path)
        payload = _manifest_payload_from_signed(mj)

        if payload.get("finalized") is True:
            return self.manifest_path

        payload["finalized"] = True
        payload["updated_at_ms"] = _now_ms()

        signed = sign_manifest(self.gw.private_key_bytes, payload)
        _write_json(self.manifest_path, signed)
        return self.manifest_path