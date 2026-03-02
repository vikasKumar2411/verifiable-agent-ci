# tests/test_policy_enforcement.py
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def _clean_env() -> dict:
    """
    Avoid test flakiness from user shell env (especially VACI_POLICY_PATH / session vars).
    """
    env = os.environ.copy()
    for k in [
        "VACI_POLICY_PATH",
        "VACI_OUT_DIR",
        "VACI_KEYFILE",
        "VACI_POLICY_ID",
        "VACI_RUN_ID",
        "VACI_TRUST",
    ]:
        env.pop(k, None)
    return env


def _run(cmd: list[str], cwd: Path, env: dict):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, env=env)


def _cli():
    return ["python", "-m", "vaci.cli"]


def test_policy_denies_and_emits_signed_denial_receipt(tmp_path: Path):
    env = _clean_env()
    root = Path.cwd()

    out = tmp_path / ".vaci"
    out.mkdir(parents=True, exist_ok=True)

    # Allow only echo; deny everything else (e.g. ls)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 1, "allow": ["echo"]}))

    # Create gateway key
    keyfile = tmp_path / "gw.key"
    p = _run(_cli() + ["keygen", "--out", str(keyfile)], cwd=root, env=env)
    assert p.returncode == 0, (p.stdout or "") + (p.stderr or "")

    run_id = "run_policy_1"

    # Allowed
    p = _run(
        _cli()
        + [
            "run",
            "--out-dir",
            str(out),
            "--keyfile",
            str(keyfile),
            "--run-id",
            run_id,
            "--policy-id",
            "demo",
            "--policy-path",
            str(policy),
            "--",
            "echo",
            "ok",
        ],
        cwd=root,
        env=env,
    )
    assert p.returncode == 0, (p.stdout or "") + (p.stderr or "")

    # Denied (should still return 0 from cmd_run because it emits a receipt+manifest)
    p = _run(
        _cli()
        + [
            "run",
            "--out-dir",
            str(out),
            "--keyfile",
            str(keyfile),
            "--run-id",
            run_id,
            "--policy-id",
            "demo",
            "--policy-path",
            str(policy),
            "--",
            "ls",
        ],
        cwd=root,
        env=env,
    )
    assert p.returncode == 0, (p.stdout or "") + (p.stderr or "")

    # Trust key
    trust = tmp_path / "trusted_keys.json"
    trust.write_text(json.dumps({"trusted_key_ids": []}))
    p = _run(
        _cli() + ["trust", "add", "--pubkey", str(out / "public_key_b64.json"), "--trust", str(trust)],
        cwd=root,
        env=env,
    )
    assert p.returncode == 0, (p.stdout or "") + (p.stderr or "")

    # Default verify should PASS (crypto + hashes only)
    p = _run(
        _cli()
        + [
            "verify-manifest",
            "--manifest",
            str(out / "run_manifest.json"),
            "--trust",
            str(trust),
            # IMPORTANT: do NOT pass --policy-path here unless you intend to enforce binding.
            # Even if you pass it, current implementation still won't fail on deny unless --enforce-policy is set.
        ],
        cwd=root,
        env=env,
    )
    assert p.returncode == 0, (p.stdout or "") + (p.stderr or "")

    # Strict verify should FAIL because there is a denied receipt
    p = _run(
        _cli()
        + [
            "verify-manifest",
            "--manifest",
            str(out / "run_manifest.json"),
            "--trust",
            str(trust),
            "--enforce-policy",
        ],
        cwd=root,
        env=env,
    )
    assert p.returncode != 0, "Expected enforce-policy to fail when denied receipt exists"
    combined = (p.stdout + p.stderr).lower()
    assert ("deny" in combined) or ("denied" in combined), combined

    # sanity: inspect denial receipt exists and is marked deny
    mj = json.loads((out / "run_manifest.json").read_text())
    receipts = mj["receipts"]
    assert len(receipts) == 2

    denied_entry = receipts[1]
    rp = out / denied_entry["receipt_path"]
    rj = json.loads(rp.read_text())
    assert rj.get("policy_decision") == "deny"
    assert isinstance(rj.get("deny_reason"), str) and rj["deny_reason"]
    assert rj.get("exit_code") == 126