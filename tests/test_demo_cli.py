from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _read_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def test_demo_cli_creates_manifest_and_denial(tmp_path: Path) -> None:
    out_dir = tmp_path / "demo_run"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Run demo deterministically into tmp_path
    cmd = [
        sys.executable,
        "-m",
        "vaci.cli",
        "demo",
        "--preset",
        "pr-agent",
        "--out-dir",
        str(out_dir),
        "--run-id",
        "demo_test_run",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode == 0, f"demo failed:\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"

    manifest = out_dir / "run_manifest.json"
    trust = out_dir / "trusted_keys.json"
    assert manifest.exists(), f"missing manifest: {manifest}"
    assert trust.exists(), f"missing trust store: {trust}"

    mj = _read_json(manifest)
    receipts = mj.get("receipts")
    assert isinstance(receipts, list), "manifest.receipts must be a list"
    assert len(receipts) == 2, f"expected 2 receipts, got {len(receipts)}"

    # Inspect referenced receipt files and ensure exactly one is denied.
    deny_count = 0
    for entry in receipts:
        assert isinstance(entry, dict)
        rp = entry.get("receipt_path")
        assert isinstance(rp, str) and rp, "receipt_path missing"
        receipt_path = (out_dir / rp).resolve()
        assert receipt_path.exists(), f"missing receipt file: {receipt_path}"

        rj = _read_json(receipt_path)
        if rj.get("policy_decision") == "deny":
            deny_count = 1

    assert deny_count == 1, f"expected exactly 1 denied receipt, got {deny_count}"

    # verify-manifest should pass using the demo trust store
    cmd2 = [
        sys.executable,
        "-m",
        "vaci.cli",
        "verify-manifest",
        "--manifest",
        str(manifest),
        "--trust",
        str(trust),
    ]
    r2 = subprocess.run(cmd2, capture_output=True, text=True)
    assert r2.returncode == 0, f"verify-manifest failed:\nSTDOUT:\n{r2.stdout}\nSTDERR:\n{r2.stderr}"