# tests/test_manifest_verify.py
from __future__ import annotations

import json
import os
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
    # Use the same invocation you used manually
    return ["python", "-m", "vaci.cli"]


def test_verify_manifest_happy_path(tmp_path: Path):
    # Run in an isolated repo-like temp dir by copying current project
    # Best-effort: rely on running from project root; for tmp_path we just use cwd=root
    root = Path.cwd()

    # 1) run
    p = _run(_python_cli_args() + ["run", "--policy-id", "demo", "--", "echo", "hello"], cwd=root)
    assert p.returncode == 0, p.stderr + "\n" + p.stdout

    # 2) trust add
    p = _run(_python_cli_args() + ["trust", "add", "--pubkey", ".vaci/public_key_b64.json"], cwd=root)
    assert p.returncode == 0, p.stderr + "\n" + p.stdout
    assert "OK: trusted key_id" in p.stdout

    # 3) verify-manifest
    p = _run(_python_cli_args() + ["verify-manifest", "--manifest", ".vaci/run_manifest.json"], cwd=root)
    assert p.returncode == 0, p.stderr + "\n" + p.stdout
    assert "OK: manifest verified" in p.stdout


def test_verify_manifest_fails_if_untrusted(tmp_path: Path):
    root = Path.cwd()

    # Clean trust store if your implementation supports it; otherwise delete the trust file if known.
    # If your trust store lives under .vaci/, wipe it to ensure untrusted state.
    # Adjust filenames below if your project uses a different trust file name.
    for candidate in [Path(".vaci/trusted_keys.json"), Path(".vaci/trust_store.json")]:
        f = root / candidate
        if f.exists():
            f.unlink()

    p = _run(_python_cli_args() + ["run", "--policy-id", "demo", "--", "echo", "hello"], cwd=root)
    assert p.returncode == 0, p.stderr + "\n" + p.stdout

    p = _run(_python_cli_args() + ["verify-manifest", "--manifest", ".vaci/run_manifest.json"], cwd=root)
    assert p.returncode == 2, p.stderr + "\n" + p.stdout
    # One of these should appear depending on your message text:
    assert ("untrusted" in (p.stdout + p.stderr).lower()) or ("trust add" in (p.stdout + p.stderr).lower())


def test_verify_manifest_fails_on_receipt_tamper(tmp_path: Path):
    root = Path.cwd()

    p = _run(_python_cli_args() + ["run", "--policy-id", "demo", "--", "echo", "hello"], cwd=root)
    assert p.returncode == 0, p.stderr + "\n" + p.stdout

    p = _run(_python_cli_args() + ["trust", "add", "--pubkey", ".vaci/public_key_b64.json"], cwd=root)
    assert p.returncode == 0, p.stderr + "\n" + p.stdout

    receipt_path = root / ".vaci/receipt.json"
    assert receipt_path.exists()

    # Tamper one byte in a JSON-safe way: toggle a boolean field if present,
    # else append a harmless space to a string field, else modify raw bytes.
    data = json.loads(receipt_path.read_text())
    mutated = False

    # Try common fields
    for k in ["cmd", "status", "stdout_sha256", "policy_id", "run_id"]:
        if k in data and isinstance(data[k], str) and data[k]:
            data[k] = data[k] + " "
            mutated = True
            break

    if not mutated:
        # fallback: raw byte flip
        b = receipt_path.read_bytes()
        if len(b) < 10:
            raise AssertionError("receipt.json unexpectedly tiny")
        b = bytearray(b)
        b[10] = (b[10] + 1) % 256
        receipt_path.write_bytes(bytes(b))
    else:
        receipt_path.write_text(json.dumps(data, indent=2, sort_keys=True))

    p = _run(_python_cli_args() + ["verify-manifest", "--manifest", ".vaci/run_manifest.json"], cwd=root)
    assert p.returncode == 2, p.stderr + "\n" + p.stdout
    assert "mismatch" in (p.stdout + p.stderr).lower() or "invalid" in (p.stdout + p.stderr).lower()