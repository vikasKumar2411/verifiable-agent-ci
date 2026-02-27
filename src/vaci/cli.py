# /Users/vikaskumar/Desktop/verifiable-agent-ci/src/vaci/cli.py
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

from vaci.trust import TrustError, assert_trusted_signer, key_id_from_receipt_json
from vaci.gateway import LocalGateway, Receipt, verify_receipt, sign_manifest

def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def _now_ms() -> int:
    return int(time.time() * 1000)

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_obj(obj: Any) -> str:
    """
    Hash a JSON-serializable object deterministically (canonical-ish JSON).
    """
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def _compute_policy_sha256(policy_path: str | None) -> str | None:
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
    Persist a gateway keyfile in the same format as cmd_keygen produces,
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
        priv = _b64.urlsafe_b64decode(priv + "==")

    # ---- coerce public key to raw bytes ----
    if hasattr(pub, "public_bytes"):
        pub = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    elif isinstance(pub, str):
        pub = _b64.urlsafe_b64decode(pub  + "==")

    if not isinstance(priv, (bytes, bytearray)) or not isinstance(pub, (bytes, bytearray)):
        raise TypeError("LocalGateway must expose raw private/public key bytes")

    priv_b = bytes(priv)
    pub_b = bytes(pub)
    key_id = hashlib.sha256(pub_b).hexdigest()

    obj = {
        "kty": "Ed25519",
        "format": "raw",
        "privkey_b64": _b64.urlsafe_b64encode(priv_b).decode("ascii").rstrip("="),
        "pubkey_b64": _b64.urlsafe_b64encode(pub_b).decode("ascii").rstrip("="),
        "key_id": key_id,
    }
    _write_json(path, obj)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def _entry_hash(entry: Dict[str, Any]) -> str:
    """
    Hash an entry excluding its own entry_hash.
    """
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    return _sha256_obj(payload)


def _manifest_payload_from_signed(mj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Take a signed manifest json dict and return the unsigned payload object
    suitable for re-signing (drops signature  manifest_hash).
    """
    payload = dict(mj)
    payload.pop("signature", None)
    payload.pop("manifest_hash", None)
    return payload

def cmd_keygen(args: argparse.Namespace) -> int:
    out_arg = Path(args.out)

    out_is_dir = (
        (out_arg.exists() and out_arg.is_dir())
        or str(args.out).endswith(os.sep)
        or (out_arg.suffix == "")
    )

    if out_is_dir:
        out_dir = out_arg
        out_dir.mkdir(parents=True, exist_ok=True)
        keyfile_path = out_dir / "gateway_ed25519.key"
        pubfile_path = out_dir / "public_key_b64.json"
    else:
        keyfile_path = out_arg
        keyfile_path.parent.mkdir(parents=True, exist_ok=True)
        pubfile_path = keyfile_path.parent / "public_key_b64.json"

    from vaci.crypto import generate_ed25519_keypair

    priv, pub = generate_ed25519_keypair()

    # Support both raw bytes and cryptography key objects
    if hasattr(priv, "private_bytes"):
        from cryptography.hazmat.primitives import serialization

        priv = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    if hasattr(pub, "public_bytes"):
        from cryptography.hazmat.primitives import serialization

        pub = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    if not isinstance(priv, (bytes, bytearray)) or not isinstance(pub, (bytes, bytearray)):
        raise TypeError("generate_ed25519_keypair() must return bytes or key objects convertible to raw bytes")

    priv = bytes(priv)
    pub = bytes(pub)

    key_id = hashlib.sha256(pub).hexdigest()

    obj = {
        "kty": "Ed25519",
        "format": "raw",
        "privkey_b64": base64.urlsafe_b64encode(priv).decode("ascii").rstrip("="),
        "pubkey_b64": base64.urlsafe_b64encode(pub).decode("ascii").rstrip("="),
        "key_id": key_id,
    }

    _write_json(keyfile_path, obj)
    _write_json(pubfile_path, {"pubkey_b64": obj["pubkey_b64"]})

    try:
        os.chmod(keyfile_path, 0o600)
    except Exception:
        pass

    print(f"OK: wrote gateway keyfile to {keyfile_path}", file=sys.stderr)
    print(f"OK: wrote public key to {pubfile_path}", file=sys.stderr)
    print(f"key_id: {key_id}", file=sys.stderr)
    return 0

def cmd_trust_add(args: argparse.Namespace) -> int:
    """
    Add a signer key_id to trusted_keys.json using a public_key_b64.json file.
    """
    pubkey_path = Path(args.pubkey)
    trust_path = Path(args.trust)

    pj = _read_json(pubkey_path)
    pub_b64 = pj.get("pubkey_b64")
    if not isinstance(pub_b64, str) or not pub_b64:
        print("FAIL: pubkey file must contain pubkey_b64", file=sys.stderr)
        return 2

    pub_raw = base64.urlsafe_b64decode(pub_b64 + "==")
    key_id = hashlib.sha256(pub_raw).hexdigest()

    if trust_path.exists():
        tj = _read_json(trust_path)
    else:
        tj = {"trusted_key_ids": []}

    ids = tj.get("trusted_key_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        print('FAIL: trust store must contain {"trusted_key_ids": [..strings..]}', file=sys.stderr)
        return 2

    if key_id not in ids:
        ids.append(key_id)
        tj["trusted_key_ids"] = sorted(set(ids))
        _write_json(trust_path, tj)

    print(f"OK: trusted key_id {key_id}", file=sys.stderr)
    return 0

def cmd_finalize(args: argparse.Namespace) -> int:
    """
    Finalize a run_manifest.json (set finalized=true) and re-sign it.
    After finalization, cmd_run will refuse to append additional receipts.
    """
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"FAIL: manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    # Load gateway key for re-sign
    try:
        gw = LocalGateway.from_keyfile(args.keyfile)
    except FileNotFoundError:
        print(f"FAIL: gateway keyfile not found: {args.keyfile}", file=sys.stderr)
        print("Hint: run: vaci keygen --out .vaci_keys/gateway_ed25519.key", file=sys.stderr)
        return 2

    mj = _read_json(manifest_path)
    payload = _manifest_payload_from_signed(mj)

    if payload.get("finalized") is True:
        print("OK: manifest already finalized", file=sys.stderr)
        return 0

    payload["finalized"] = True
    payload["updated_at_ms"] = _now_ms()

    signed = sign_manifest(gw.private_key_bytes, payload)
    _write_json(manifest_path, signed)

    print(f"OK: manifest finalized: {manifest_path}", file=sys.stderr)
    return 0

def cmd_run(args: argparse.Namespace) -> int:
    import base64 as _b64
    from cryptography.hazmat.primitives import serialization
    import uuid

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    run_id = getattr(args, "run_id", None) or os.environ.get("VACI_RUN_ID") or uuid.uuid4().hex
    call_id = getattr(args, "call_id", None) or uuid.uuid4().hex
    policy_id = getattr(args, "policy_id", None) or os.environ.get("VACI_POLICY_ID") or "dev"
    policy_path = getattr(args, "policy_path", None) or os.environ.get("VACI_POLICY_PATH")
    try:
        policy_sha256 = _compute_policy_sha256(policy_path)
    except FileNotFoundError as e:
        print(f"FAIL: policy file not found: {e}", file=sys.stderr)
        return 2

    # Commit 2: persistent gateway by default
    if getattr(args, "ephemeral", False):
        # IMPORTANT: keep ephemeral signer stable across a session (same out_dir),
        # otherwise manifest signature will flip every run and verification fails.
        ephem_keyfile = out_dir / "ephemeral_gateway_ed25519.key"
        if ephem_keyfile.exists():
            gw = LocalGateway.from_keyfile(str(ephem_keyfile))
        else:
            gw = LocalGateway.ephemeral()
            _write_gateway_keyfile(ephem_keyfile, gw)
    else:
        try:
            keyfile = getattr(args, "keyfile", ".vaci_keys/gateway_ed25519.key")
            gw = LocalGateway.from_keyfile(keyfile)
        except FileNotFoundError:
            print(f"FAIL: gateway keyfile not found: {keyfile}", file=sys.stderr)
            print("Hint: run: vaci keygen --out .vaci_keys/gateway_ed25519.key", file=sys.stderr)
            return 2

    # ---- V2: enforce policy BEFORE execution ----
    deny_reason = None
    if policy_path:
        try:
            from vaci.core.policy import load_policy, evaluate

            pol = load_policy(policy_path)
            dec = evaluate(pol, args.command, cwd=args.cwd or os.getcwd())
            if not dec.allowed:
                deny_reason = dec.reason
        except Exception as e:
            # Policy read/parse errors are treated as hard fail (safer default)
            print(f"FAIL: policy evaluation error: {e}", file=sys.stderr)
            return 2

    if deny_reason is not None:
        receipt = gw.run_denied(
            args.command,
            cwd=args.cwd,
            run_id=run_id,
            policy_id=policy_id,
            call_id=call_id,
            policy_sha256=policy_sha256,
            deny_reason=deny_reason,
        )
    else:
        receipt = gw.run(
            args.command,
            cwd=args.cwd,
            run_id=run_id,
            policy_id=policy_id,
            call_id=call_id,
            policy_sha256=policy_sha256,
        )

    pk = gw.public_key
    # Support both "raw bytes" or "cryptography key object"
    if hasattr(pk, "public_bytes"):
        pubkey_bytes = pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    else:
        pubkey_bytes = pk

    # Per-call artifacts (session mode)
    receipt_name = f"receipt_{call_id}.json"
    pubkey_name = f"public_key_{call_id}.json"

    pubkey_path = out_dir / pubkey_name
    _write_json(
        pubkey_path,
        {"pubkey_b64": _b64.urlsafe_b64encode(pubkey_bytes).decode("ascii").rstrip("=")},
    )

    receipt_path = out_dir / receipt_name
    _write_json(receipt_path, receipt.to_dict())

    # Back-compat / convenience: also write the "latest" filenames
    _write_json(out_dir / "public_key_b64.json", {"pubkey_b64": _b64.urlsafe_b64encode(pubkey_bytes).decode("ascii").rstrip("=")})
    _write_json(out_dir / "receipt.json", receipt.to_dict())

    # ---- NEW: run manifest ----
    import subprocess

    manifest_path = out_dir / "run_manifest.json"

    try:
        git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        git_sha = None


    # Safety: if manifest exists, require explicit run-id (or env VACI_RUN_ID) to append.
    if manifest_path.exists() and not (getattr(args, "run_id", None) or os.environ.get("VACI_RUN_ID")):
        print(
            "FAIL: manifest exists; refusing to append without explicit --run-id (or env VACI_RUN_ID)\n"
            "Hint: either:\n"
            "  - pass --run-id <same as the existing manifest>, or\n"
            "  - start a new session (rm -rf .vaci / use a different --out-dir).",
            file=sys.stderr,
        )
        return 2

    entry = {
        "call_id": call_id,
        "created_at_ms": _now_ms(),
        "receipt_path": receipt_path.name,
        "receipt_sha256": _sha256_file(receipt_path),
        "pubkey_path": pubkey_path.name,
        "pubkey_sha256": _sha256_file(pubkey_path),
        "policy_sha256": policy_sha256,
    }

    if manifest_path.exists():
        mj = _read_json(manifest_path)
        payload = _manifest_payload_from_signed(mj)

        # enforce session invariants
        if payload.get("finalized") is True:
            print(
                "FAIL: manifest is finalized; refusing to append\n"
                "Hint: start a new session by:\n"
                "  - removing the out-dir (e.g. rm -rf .vaci), or\n"
                "  - using a different --out-dir, or\n"
                "  - using a new run_id in a fresh directory.",
                file=sys.stderr,
            )
            return 2

        if payload.get("run_id") != run_id:
            print(f"FAIL: run_id mismatch vs existing manifest ({payload.get('run_id')} != {run_id})", file=sys.stderr)
            return 2
        if payload.get("policy_id") != policy_id:
            print(f"FAIL: policy_id mismatch vs existing manifest ({payload.get('policy_id')} != {policy_id})", file=sys.stderr)
            return 2

        if payload.get("policy_sha256") != policy_sha256:
            print("FAIL: policy_sha256 mismatch vs existing manifest", file=sys.stderr)
            print(f"  expected: {payload.get('policy_sha256')}", file=sys.stderr)
            print(f"  got: {policy_sha256}", file=sys.stderr)
            return 2

        receipts = payload.get("receipts")
        if not isinstance(receipts, list):
            print("FAIL: manifest payload receipts must be a list", file=sys.stderr)
            return 2

        # keep created_at_ms stable; bump updated_at_ms
        payload.setdefault("created_at_ms", _now_ms())
        payload["updated_at_ms"] = _now_ms()
        payload.setdefault("finalized", False)
        payload.setdefault("policy_sha256", policy_sha256)

        # preserve git_sha from first creation unless missing
        if payload.get("git_sha") is None:
            payload["git_sha"] = git_sha

        # chain hashes
        prev = receipts[-1].get("entry_hash") if receipts else None
        entry["prev_entry_hash"] = prev
        entry["entry_hash"] = _entry_hash(entry)

        receipts.append(entry)
    else:
        entry["prev_entry_hash"] = None
        entry["entry_hash"] = _entry_hash(entry)
        payload = {
            "run_id": run_id,
            "policy_id": policy_id,
            "git_sha": git_sha,
            "created_at_ms": _now_ms(),
            "updated_at_ms": _now_ms(),
            "finalized": False,
            "policy_sha256": policy_sha256,
            "receipts": [entry],
        }

    signed_manifest = sign_manifest(gw.private_key_bytes, payload)
    _write_json(manifest_path, signed_manifest)
    # --------------------------

    return 0

def cmd_verify_manifest(args: argparse.Namespace) -> int:
    """
    Verify a run_manifest.json:
      1) manifest_hash matches canonical payload (excluding signature; may include or exclude manifest_hash)
      2) signature verifies against the same payload variant
      3) trust-root check passes for signer key_id
      4) referenced files match their sha256
      5) receipts verify cryptographically and are consistent with run_id/policy_id
    """
    import base64 as _b64
    from pathlib import Path

    from vaci.crypto import hashref_sha256_from_obj, verify_obj_ed25519
    from vaci.schema import Signature

    manifest_path = Path(args.manifest)
    mj = _read_json(manifest_path)

    require_finalized = bool(getattr(args, "require_finalized", False))
    policy_path = getattr(args, "policy_path", None) or os.environ.get("VACI_POLICY_PATH")
    try:
        policy_sha256_expected = _compute_policy_sha256(policy_path) if policy_path else None
    except FileNotFoundError as e:
        print(f"FAIL: policy file not found: {e}", file=sys.stderr)
        return 2

    # -------- helpers --------
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _abs_from_manifest(rel_or_abs: str) -> Path:
        p = Path(rel_or_abs)
        if p.is_absolute():
            return p
        # interpret relative paths as relative to manifest file location
        return (manifest_path.parent / p).resolve()

    # -------- basic shape checks --------
    sig_obj = mj.get("signature")
    if not isinstance(sig_obj, dict):
        print("FAIL: manifest missing signature", file=sys.stderr)
        return 2

    declared_href = mj.get("manifest_hash")
    if not isinstance(declared_href, dict) or declared_href.get("alg") != "sha256":
        print("FAIL: manifest missing manifest_hash", file=sys.stderr)
        return 2

    declared_hex = declared_href.get("hex")
    declared_size = declared_href.get("size_bytes")
    if not isinstance(declared_hex, str) or not isinstance(declared_size, int):
        print("FAIL: manifest_hash must contain {alg, hex(str), size_bytes(int)}", file=sys.stderr)
        return 2

    receipts = mj.get("receipts") or []
    if not isinstance(receipts, list) or not receipts:
        print("FAIL: manifest missing receipts[]", file=sys.stderr)
        return 2

    # -------- find pubkey_path (overrideable) --------
    pubkey_override = getattr(args, "pubkey", None)
    if pubkey_override:
        pubkey_path = Path(pubkey_override)
        if not pubkey_path.is_absolute():
            pubkey_path = (Path.cwd() / pubkey_path).resolve()
    else:
        first = receipts[0]
        if not isinstance(first, dict) or "pubkey_path" not in first:
            print("FAIL: manifest receipts[0] missing pubkey_path", file=sys.stderr)
            return 2
        pubkey_path = _abs_from_manifest(first["pubkey_path"])

    pj = _read_json(pubkey_path)
    pub_b64 = pj.get("pubkey_b64")
    if not isinstance(pub_b64, str) or not pub_b64:
        print("FAIL: pubkey file must contain pubkey_b64", file=sys.stderr)
        return 2

    pubkey_raw = _b64.urlsafe_b64decode(pub_b64 + "==")
    # IMPORTANT: vaci.crypto.verify_obj_ed25519 expects raw pubkey bytes (not a cryptography key object)
    pubkey = pubkey_raw

    # -------- Variant-B only --------
    payload_b = dict(mj)
    payload_b.pop("signature", None)
    payload_b.pop("manifest_hash", None)

    href_b, _ = hashref_sha256_from_obj(payload_b)

    if not (href_b.hex == declared_hex and href_b.size_bytes == declared_size):
        print("FAIL: manifest_hash mismatch (expected Variant-B)", file=sys.stderr)
        return 2

    payload_for_sig = payload_b

    # -------- signature check --------
    try:
        sig = Signature(**sig_obj)
    except Exception as e:
        print(f"FAIL: invalid manifest signature object: {e}", file=sys.stderr)
        return 2

    if not verify_obj_ed25519(pubkey, payload_for_sig, sig):
        print("FAIL: manifest signature verification failed", file=sys.stderr)
        return 2

    # -------- trust root check for signer (enforce allowlist here) --------
    signer_key_id = hashlib.sha256(pubkey_raw).hexdigest()

    trust_path = Path(args.trust).expanduser()
    if not trust_path.is_absolute():
        # interpret relative trust paths relative to current working dir
        trust_path = (Path.cwd() / trust_path).resolve()

    if trust_path.exists():
        try:
            tj = _read_json(trust_path)
        except Exception as e:
            print(f"FAIL: could not read trust store {trust_path}: {e}", file=sys.stderr)
            return 2
    else:
        tj = {"trusted_key_ids": []}

    ids = tj.get("trusted_key_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        print('FAIL: trust store must contain {"trusted_key_ids": [..strings..]}', file=sys.stderr)
        return 2

    if signer_key_id not in set(ids):
        print(f"FAIL: untrusted signer key_id {signer_key_id}", file=sys.stderr)
        print(
            f"Hint: python -m vaci.cli trust add --pubkey .vaci/public_key_b64.json --trust {trust_path}",
            file=sys.stderr,
        )
        return 2

    # -------- verify referenced files + receipts --------
    run_id = mj.get("run_id")
    policy_id = mj.get("policy_id")

    manifest_policy_sha256 = mj.get("policy_sha256")

    if policy_sha256_expected is not None and manifest_policy_sha256 != policy_sha256_expected:
        print("FAIL: manifest policy_sha256 does not match provided policy-path", file=sys.stderr)
        print(f"  expected: {policy_sha256_expected}", file=sys.stderr)
        print(f"  got: {manifest_policy_sha256}", file=sys.stderr)
        return 2

    if require_finalized and mj.get("finalized") is not True:
        print("FAIL: manifest is not finalized", file=sys.stderr)
        print("Hint: run: python -m vaci.cli finalize --manifest <path> --keyfile <key>", file=sys.stderr)
        return 2

    if run_id is not None and not isinstance(run_id, str):
        print("FAIL: manifest run_id must be a string if present", file=sys.stderr)
        return 2
    if policy_id is not None and not isinstance(policy_id, str):
        print("FAIL: manifest policy_id must be a string if present", file=sys.stderr)
        return 2

    # -------- verify receipt entry chain (reorder/delete detection) --------
    prev = None
    for i, e in enumerate(receipts):
        if not isinstance(e, dict):
            print(f"FAIL: receipts[{i}] is not an object", file=sys.stderr)
            return 2
        if e.get("prev_entry_hash") != prev:
            print(f"FAIL: receipt chain broken at index {i}", file=sys.stderr)
            return 2
        eh = e.get("entry_hash")
        if not isinstance(eh, str) or not eh:
            print(f"FAIL: receipts[{i}] missing entry_hash", file=sys.stderr)
            return 2
        calc = _entry_hash(e)
        if calc != eh:
            print(f"FAIL: receipts[{i}] entry_hash mismatch", file=sys.stderr)
            return 2
        prev = eh

    for i, entry in enumerate(receipts):
        if not isinstance(entry, dict):
            print(f"FAIL: receipts[{i}] is not an object", file=sys.stderr)
            return 2

        for k in ("receipt_path", "receipt_sha256", "pubkey_path", "pubkey_sha256", "call_id"):
            if k not in entry:
                print(f"FAIL: receipts[{i}] missing {k}", file=sys.stderr)
                return 2

        rp = _abs_from_manifest(entry["receipt_path"])
        pp = _abs_from_manifest(entry["pubkey_path"])

        # receipt sha
        actual_receipt = _sha256_file(rp)
        expected_receipt = entry.get("receipt_sha256")
        if actual_receipt != expected_receipt:
            print("FAIL: receipt sha256 mismatch", file=sys.stderr)
            print(f"  file: {rp}", file=sys.stderr)
            print(f"  expected: {expected_receipt}", file=sys.stderr)
            print(f"  got: {actual_receipt}", file=sys.stderr)
            return 2

        # pubkey sha
        actual_pubkey = _sha256_file(pp)
        expected_pubkey = entry.get("pubkey_sha256")
        if actual_pubkey != expected_pubkey:
            print("FAIL: pubkey sha256 mismatch", file=sys.stderr)
            print(f"  file: {pp}", file=sys.stderr)
            print(f"  expected: {expected_pubkey}", file=sys.stderr)
            print(f"  got: {actual_pubkey}", file=sys.stderr)
            return 2

        # ---- OPTIONAL: toolcall sidecar binding (agent runner) ----
        toolcall_rel = entry.get("toolcall_path")
        if toolcall_rel is not None:
            if not isinstance(toolcall_rel, str) or not toolcall_rel:
                print(f"FAIL: receipts[{i}] toolcall_path must be a non-empty string", file=sys.stderr)
                return 2

            expected_toolcall = entry.get("toolcall_sha256")
            if not isinstance(expected_toolcall, str) or not expected_toolcall:
                print(f"FAIL: receipts[{i}] missing toolcall_sha256", file=sys.stderr)
                return 2

            tp = _abs_from_manifest(toolcall_rel)
            if not tp.exists():
                print("FAIL: toolcall file missing", file=sys.stderr)
                print(f"  file: {tp}", file=sys.stderr)
                return 2

            actual_toolcall = _sha256_file(tp)
            if actual_toolcall != expected_toolcall:
                print("FAIL: toolcall sha256 mismatch", file=sys.stderr)
                print(f"  file: {tp}", file=sys.stderr)
                print(f"  expected: {expected_toolcall}", file=sys.stderr)
                print(f"  got: {actual_toolcall}", file=sys.stderr)
                return 2
                        # Deep-verify toolcall content (optional but recommended):
            # - ensure required fields exist
            # - verify toolcall_record_sha256 binds (tool,args,result)
            try:
                tcj = _read_json(tp)
            except Exception as e:
                print("FAIL: could not read toolcall json", file=sys.stderr)
                print(f"  file: {tp}", file=sys.stderr)
                print(f"  error: {e}", file=sys.stderr)
                return 2

            tool = tcj.get("tool")
            args_j = tcj.get("args")
            result_j = tcj.get("result")
            if not isinstance(tool, str) or not tool:
                print("FAIL: toolcall missing tool", file=sys.stderr)
                print(f"  file: {tp}", file=sys.stderr)
                return 2
            if "args" not in tcj or "result" not in tcj:
                print("FAIL: toolcall missing args/result", file=sys.stderr)
                print(f"  file: {tp}", file=sys.stderr)
                return 2

            # Verify args_sha256/result_sha256 if present in the toolcall file
            args_sha = tcj.get("args_sha256")
            if args_sha is not None:
                if not isinstance(args_sha, str) or not args_sha:
                    print("FAIL: toolcall args_sha256 must be a non-empty string when present", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    return 2
                calc_args_sha = _sha256_obj(args_j)
                if calc_args_sha != args_sha:
                    print("FAIL: toolcall args_sha256 mismatch", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    print(f"  expected: {args_sha}", file=sys.stderr)
                    print(f"  got: {calc_args_sha}", file=sys.stderr)
                    return 2

            result_sha = tcj.get("result_sha256")
            if result_sha is not None:
                if not isinstance(result_sha, str) or not result_sha:
                    print("FAIL: toolcall result_sha256 must be a non-empty string when present", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    return 2
                calc_result_sha = _sha256_obj(result_j)
                if calc_result_sha != result_sha:
                    print("FAIL: toolcall result_sha256 mismatch", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    print(f"  expected: {result_sha}", file=sys.stderr)
                    print(f"  got: {calc_result_sha}", file=sys.stderr)
                    return 2

            # Verify record binding hash against entry or file (entry wins if present)
            calc_record_sha = _sha256_obj({"tool": tool, "args": args_j, "result": result_j})
            expected_record_sha = entry.get("toolcall_record_sha256") or tcj.get("toolcall_record_sha256")
            if expected_record_sha is not None:
                if not isinstance(expected_record_sha, str) or not expected_record_sha:
                    print("FAIL: toolcall_record_sha256 must be a non-empty string when present", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    return 2
                if calc_record_sha != expected_record_sha:
                    print("FAIL: toolcall_record_sha256 mismatch", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    print(f"  expected: {expected_record_sha}", file=sys.stderr)
                    print(f"  got: {calc_record_sha}", file=sys.stderr)
                    return 2


        # policy binding per entry (optional unless policy-path supplied)
        if policy_sha256_expected is not None:
            if entry.get("policy_sha256") != policy_sha256_expected:
                print(f"FAIL: receipts[{i}] policy_sha256 mismatch vs policy-path", file=sys.stderr)
                return 2

        # Load pubkey + verify receipt cryptographically
        pj2 = _read_json(pp)
        pub_b64_2 = pj2.get("pubkey_b64")
        if not isinstance(pub_b64_2, str) or not pub_b64_2:
            print(f"FAIL: pubkey file invalid: {pp}", file=sys.stderr)
            return 2
        pub_raw_2 = _b64.urlsafe_b64decode(pub_b64_2 + "==")

        rj = _read_json(rp)
        sig2 = rj.get("signature")
        if not isinstance(sig2, dict):
            print(f"FAIL: receipt missing signature: {rp}", file=sys.stderr)
            return 2

        try:
            receipt = Receipt(
                run_id=rj["run_id"],
                policy_id=rj["policy_id"],
                call_id=rj["call_id"],
                command=rj["command"],
                cwd=rj["cwd"],
                started_at_ms=rj["started_at_ms"],
                finished_at_ms=rj["finished_at_ms"],
                exit_code=rj["exit_code"],
                stdout_b64=rj["stdout_b64"],
                stderr_b64=rj["stderr_b64"],
                stdout_sha256_b64=rj["stdout_sha256_b64"],
                stderr_sha256_b64=rj["stderr_sha256_b64"],
                policy_sha256=rj.get("policy_sha256"),
                policy_decision=rj.get("policy_decision"),
                deny_reason=rj.get("deny_reason"),
                signature=Signature(**sig2),
            )
        except Exception as e:
            print(f"FAIL: invalid receipt schema for {rp}: {e}", file=sys.stderr)
            return 2

        if not verify_receipt(pub_raw_2, receipt):
            print(f"FAIL: receipt verification failed for {rp}", file=sys.stderr)
            return 2

        # ---- V2: if policy-path is supplied, enforce that denied receipts fail verification ----
        if policy_sha256_expected is not None:
            # receipt JSON may be V1 (no policy_decision); treat missing as "allow"
            decision = rj.get("policy_decision", "allow")
            if decision == "deny":
                reason = rj.get("deny_reason") or "policy denied"
                print(f"FAIL: receipt denied by policy: {reason}", file=sys.stderr)
                return 2

        # Consistency checks vs manifest
        if run_id is not None and receipt.run_id != run_id:
            print(f"FAIL: receipt.run_id mismatch for {rp}", file=sys.stderr)
            return 2
        if policy_id is not None and receipt.policy_id != policy_id:
            print(f"FAIL: receipt.policy_id mismatch for {rp}", file=sys.stderr)
            return 2
        if receipt.call_id != entry["call_id"]:
            print(f"FAIL: receipt.call_id mismatch for {rp}", file=sys.stderr)
            return 2

    print("OK: manifest verified", file=sys.stderr)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    import base64 as _b64

    receipt_path = Path(args.receipt)
    pubkey_path = Path(args.pubkey)

    rj = _read_json(receipt_path)
    pj = _read_json(pubkey_path)

    pubkey_raw = _b64.urlsafe_b64decode(pj["pubkey_b64"] + "==")
    sig = rj["signature"]

    receipt = Receipt(
        run_id=rj["run_id"],
        policy_id=rj["policy_id"],
        call_id=rj["call_id"],
        command=rj["command"],
        cwd=rj["cwd"],
        started_at_ms=rj["started_at_ms"],
        finished_at_ms=rj["finished_at_ms"],
        exit_code=rj["exit_code"],
        stdout_b64=rj["stdout_b64"],
        stderr_b64=rj["stderr_b64"],
        stdout_sha256_b64=rj["stdout_sha256_b64"],
        stderr_sha256_b64=rj["stderr_sha256_b64"],
        # V2 fields are OPTIONAL but MUST be included when present,
        # otherwise verify_receipt() will fall back to V1 payload and
        # signature verification will fail for V2-signed receipts.
        policy_sha256=rj.get("policy_sha256"),
        policy_decision=rj.get("policy_decision"),
        deny_reason=rj.get("deny_reason"),
        signature=__import__("vaci.schema", fromlist=["Signature"]).Signature(**sig),
    )
    ok = verify_receipt(pubkey_raw, receipt)
    if not ok:
        print("FAIL: receipt verification failed", file=sys.stderr)
        return 2

    # Trust root enforcement (must be after signature verification)
    try:
        key_id = key_id_from_receipt_json(rj, pubkey_raw)
        assert_trusted_signer(key_id=key_id, trust_path=args.trust)
    except TrustError as e:
        print(f"FAIL: trust check failed: {e}", file=sys.stderr)
        return 2

    print("OK: receipt verified", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vaci")
    sp = ap.add_subparsers(dest="cmd", required=True)

    # Commit 2: keygen
    keyp = sp.add_parser("keygen", help="Generate a persistent gateway Ed25519 keyfile")
    keyp.add_argument(
        "--out",
        default=".vaci",
        help="Output dir or keyfile path. If a directory, writes gateway_ed25519.key  public_key_b64.json there (default: .vaci)",
    )

    keyp.set_defaults(fn=cmd_keygen)

    # Commit 2: trust add
    trustp = sp.add_parser("trust", help="Manage trusted signer keys")
    trustsp = trustp.add_subparsers(dest="trust_cmd", required=True)

    trust_add = trustsp.add_parser(
        "add",
        help="Add a signer key_id to trusted_keys.json using a public_key_b64.json file",
    )
    trust_add.add_argument("--pubkey", required=True, help="Path to public_key_b64.json")
    trust_add.add_argument("--trust", default=".vaci/trusted_keys.json", help="Trust store path (default: trusted_keys.json)")
    trust_add.set_defaults(fn=cmd_trust_add)

    runp = sp.add_parser("run", help="Run a command and emit signed receipt artifacts")
    runp.add_argument("--out-dir", default=".vaci", help="Directory to write receipt artifacts")
    runp.add_argument("--cwd", default=None, help="Working directory")
    runp.add_argument("--keyfile", default=".vaci/gateway_ed25519.key", help="Gateway private keyfile")


    runp.add_argument("--ephemeral", action="store_true", help="Use ephemeral key (dev/tests)")

    # NEW: ids
    runp.add_argument("--run-id", default=None, help="Run id (default: auto-generated)")
    runp.add_argument(
        "--policy-id",
        default=os.environ.get("VACI_POLICY_ID"),
        help="Policy id (default: env VACI_POLICY_ID)",
    )
    runp.add_argument("--call-id", default=None, help="Call id (default: auto-generated per invocation)")
    runp.add_argument("--policy-path", default=None, help="Path to policy file; binds sha256 into receipts+manifest")

    runp.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute (use: vaci run -- <cmd>)")
    runp.set_defaults(fn=cmd_run)

    finp = sp.add_parser("finalize", help="Finalize run_manifest.json (lock session; prevents further appends)")
    finp.add_argument("--manifest", default=".vaci/run_manifest.json", help="Path to run_manifest.json")
    finp.add_argument(
    "--keyfile",
    default=".vaci/gateway_ed25519.key",
    help="Gateway private keyfile used to sign the manifest",
)
    finp.set_defaults(fn=cmd_finalize)

    verp = sp.add_parser("verify", help="Verify a receipt artifact")
    verp.add_argument("--receipt", default=".vaci/receipt.json")
    verp.add_argument("--pubkey", default=".vaci/public_key_b64.json")
    verp.add_argument(
        "--trust",
        default=".vaci/trusted_keys.json",
        help="Path to trusted signer key allowlist (default: trusted_keys.json)",
    )
    verp.set_defaults(fn=cmd_verify)

    mp = sp.add_parser("verify-manifest", help="Verify run_manifest.json (signature + hashes + receipts)")
    mp.add_argument("--manifest", default=".vaci/run_manifest.json")
    mp.add_argument(
        "--trust",
        default=".vaci/trusted_keys.json",
        help="Path to trusted signer key allowlist (default: trusted_keys.json)",
    )
    mp.add_argument("--pubkey", default=None, help="Optional override pubkey file (otherwise uses manifest receipts[0])")
    mp.add_argument("--require-finalized", action="store_true", help="Fail unless manifest finalized=true")
    mp.add_argument("--policy-path", default=None, help="Policy file path; recompute sha256 and compare to manifest")
    mp.set_defaults(fn=cmd_verify_manifest)

    args = ap.parse_args(argv)

    if args.cmd == "run":
        # strip leading "--" if present
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        if not args.command:
            ap.error("vaci run requires a command: vaci run -- <cmd>")

    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())