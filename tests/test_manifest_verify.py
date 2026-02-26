# tests/test_manifest_verify.py
from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _run(cmd: list[str], cwd: Path, env: dict | None = None):
    """Run a command; return CompletedProcess."""
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
    )


def _python_cli_args() -> list[str]:
    return ["python", "-m", "vaci.cli"]


def _unsigned_manifest_payload(mj: dict) -> dict:
    """Return payload portion of signed manifest (drop signature + manifest_hash)."""
    payload = dict(mj)
    payload.pop("signature", None)
    payload.pop("manifest_hash", None)
    return payload


def test_verify_manifest_happy_path(tmp_path: Path):
    root = Path.cwd()
    out_dir = tmp_path / "vaci_out"
    trust_path = out_dir / "trusted_keys.json"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) run (write artifacts into tmp out_dir)
    p = _run(
        _python_cli_args() + ["run", "--out-dir", str(out_dir), "--policy-id", "demo", "--", "echo", "hello"],
        cwd=root,
    )
    assert p.returncode == 0, p.stderr + "\n" + p.stdout

    # 2) trust add (use "latest" pubkey file for convenience)
    p = _run(
        _python_cli_args()
        + ["trust", "add", "--pubkey", str(out_dir / "public_key_b64.json"), "--trust", str(trust_path)],
        cwd=root,
    )
    assert p.returncode == 0, p.stderr + "\n" + p.stdout
    out = (p.stdout or "") + (p.stderr or "")
    assert "OK: trusted key_id" in out

    # 3) verify-manifest
    p = _run(
        _python_cli_args()
        + ["verify-manifest", "--manifest", str(out_dir / "run_manifest.json"), "--trust", str(trust_path)],
        cwd=root,
    )
    assert p.returncode == 0, p.stderr + "\n" + p.stdout
    out = (p.stdout or "") + (p.stderr or "")
    assert "OK: manifest verified" in out


def test_verify_manifest_fails_if_untrusted(tmp_path: Path):
    root = Path.cwd()
    out_dir = tmp_path / "vaci_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) run
    p = _run(
        _python_cli_args() + ["run", "--out-dir", str(out_dir), "--policy-id", "demo", "--", "echo", "hello"],
        cwd=root,
    )
    assert p.returncode == 0, p.stderr + "\n" + p.stdout

    # 2) empty trust store -> must fail
    trust_path = tmp_path / "trusted_keys.json"
    trust_path.write_text(json.dumps({"trusted_key_ids": []}, indent=2))

    p = _run(
        _python_cli_args()
        + ["verify-manifest", "--manifest", str(out_dir / "run_manifest.json"), "--trust", str(trust_path)],
        cwd=root,
    )
    out = (p.stdout or "") + (p.stderr or "")
    assert p.returncode == 2, out
    assert ("untrusted" in out.lower()) or ("trust add" in out.lower())


def test_verify_manifest_fails_on_receipt_tamper(tmp_path: Path):
    root = Path.cwd()
    out_dir = tmp_path / "vaci_out"
    trust_path = out_dir / "trusted_keys.json"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) run
    p = _run(
        _python_cli_args() + ["run", "--out-dir", str(out_dir), "--policy-id", "demo", "--", "echo", "hello"],
        cwd=root,
    )
    assert p.returncode == 0, p.stderr + "\n" + p.stdout

    # 2) trust add
    p = _run(
        _python_cli_args()
        + ["trust", "add", "--pubkey", str(out_dir / "public_key_b64.json"), "--trust", str(trust_path)],
        cwd=root,
    )
    assert p.returncode == 0, p.stderr + "\n" + p.stdout

    # 3) locate the receipt referenced by the manifest (NOT just out_dir/receipt.json)
    manifest_path = out_dir / "run_manifest.json"
    mj = json.loads(manifest_path.read_text())
    payload = _unsigned_manifest_payload(mj)

    assert payload.get("receipts"), "manifest missing receipts[]"
    first = payload["receipts"][0]
    receipt_path = out_dir / first["receipt_path"]
    assert receipt_path.exists()

    # 4) tamper receipt
    data = json.loads(receipt_path.read_text())
    mutated = False

    for k in ["command", "cwd", "policy_id", "run_id", "call_id"]:
        if k in data and isinstance(data[k], str) and data[k]:
            data[k] = data[k] + " "
            mutated = True
            break

    if not mutated:
        # fallback: raw byte flip
        b = receipt_path.read_bytes()
        if len(b) < 20:
            raise AssertionError("receipt.json unexpectedly tiny")
        bb = bytearray(b)
        bb[10] = (bb[10] + 1) % 256
        receipt_path.write_bytes(bytes(bb))
    else:
        receipt_path.write_text(json.dumps(data, indent=2, sort_keys=True))

    # 5) verify-manifest must now fail
    p = _run(
        _python_cli_args()
        + ["verify-manifest", "--manifest", str(out_dir / "run_manifest.json"), "--trust", str(trust_path)],
        cwd=root,
    )
    out = (p.stdout or "") + (p.stderr or "")
    assert p.returncode == 2, out
    assert ("mismatch" in out.lower()) or ("invalid" in out.lower()) or ("tamper" in out.lower())