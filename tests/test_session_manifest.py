from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _run(cmd: list[str], cwd: Path, env: dict | None = None):
    return subprocess.run(cmd, cwd=str(cwd), env=env, text=True, capture_output=True)


def _cli():
    return ["python", "-m", "vaci.cli"]


def _write_policy(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "policy.json"
    p.write_text(content)
    return p


def test_session_appends_two_calls_and_verifies(tmp_path: Path):
    root = Path.cwd()
    out = tmp_path / ".vaci"
    policy = _write_policy(tmp_path, '{"version":1,"allow":["echo"]}')

    run_id = "run_session_1"

    p = _run(_cli() + ["run", "--ephemeral", "--out-dir", str(out), "--run-id", run_id, "--policy-id", "demo", "--policy-path", str(policy), "--", "echo", "hello"], cwd=root)
    assert p.returncode == 0, (p.stdout or "") + (p.stderr or "")

    p = _run(_cli() + ["run", "--ephemeral", "--out-dir", str(out), "--run-id", run_id, "--policy-id", "demo", "--policy-path", str(policy), "--", "echo", "world"], cwd=root)
    assert p.returncode == 0, (p.stdout or "") + (p.stderr or "")

    # trust store for this test
    trust = tmp_path / "trusted_keys.json"
    trust.write_text(json.dumps({"trusted_key_ids": []}))

    # add key from latest pubkey file
    p = _run(_cli() + ["trust", "add", "--pubkey", str(out / "public_key_b64.json"), "--trust", str(trust)], cwd=root)
    assert p.returncode == 0

    p = _run(_cli() + ["verify-manifest", "--manifest", str(out / "run_manifest.json"), "--trust", str(trust), "--policy-path", str(policy)], cwd=root)
    assert p.returncode == 0, (p.stdout or "") + (p.stderr or "")

    mj = json.loads((out / "run_manifest.json").read_text())
    assert len(mj["receipts"]) == 2


def test_finalize_locks_session(tmp_path: Path):
    root = Path.cwd()
    out = tmp_path / ".vaci"
    policy = _write_policy(tmp_path, '{"version":1}')

    run_id = "run_session_2"

    p = _run(_cli() + ["keygen", "--out", str(tmp_path / "gw.key")], cwd=root)
    assert p.returncode == 0

    p = _run(_cli() + ["run", "--out-dir", str(out), "--keyfile", str(tmp_path / "gw.key"), "--run-id", run_id, "--policy-id", "demo", "--policy-path", str(policy), "--", "echo", "hello"], cwd=root)
    assert p.returncode == 0

    p = _run(_cli() + ["finalize", "--manifest", str(out / "run_manifest.json"), "--keyfile", str(tmp_path / "gw.key")], cwd=root)
    assert p.returncode == 0

    # appending after finalize must fail
    p = _run(_cli() + ["run", "--out-dir", str(out), "--keyfile", str(tmp_path / "gw.key"), "--run-id", run_id, "--policy-id", "demo", "--policy-path", str(policy), "--", "echo", "nope"], cwd=root)
    assert p.returncode == 2


def test_verify_require_finalized(tmp_path: Path):
    root = Path.cwd()
    out = tmp_path / ".vaci"
    policy = _write_policy(tmp_path, '{"version":1}')
    trust = tmp_path / "trusted_keys.json"
    trust.write_text(json.dumps({"trusted_key_ids": []}))

    p = _run(_cli() + ["keygen", "--out", str(tmp_path / "gw.key")], cwd=root)
    assert p.returncode == 0

    run_id = "run_session_3"
    p = _run(_cli() + ["run", "--out-dir", str(out), "--keyfile", str(tmp_path / "gw.key"), "--run-id", run_id, "--policy-id", "demo", "--policy-path", str(policy), "--", "echo", "hello"], cwd=root)
    assert p.returncode == 0

    p = _run(_cli() + ["trust", "add", "--pubkey", str(out / "public_key_b64.json"), "--trust", str(trust)], cwd=root)
    assert p.returncode == 0

    # require-finalized should fail before finalize
    p = _run(_cli() + ["verify-manifest", "--manifest", str(out / "run_manifest.json"), "--trust", str(trust), "--require-finalized"], cwd=root)
    assert p.returncode == 2

    p = _run(_cli() + ["finalize", "--manifest", str(out / "run_manifest.json"), "--keyfile", str(tmp_path / "gw.key")], cwd=root)
    assert p.returncode == 0

    p = _run(_cli() + ["verify-manifest", "--manifest", str(out / "run_manifest.json"), "--trust", str(trust), "--require-finalized"], cwd=root)
    assert p.returncode == 0


def test_chain_breaks_on_reorder(tmp_path: Path):
    root = Path.cwd()
    out = tmp_path / ".vaci"
    policy = _write_policy(tmp_path, '{"version":1}')
    run_id = "run_session_4"

    p = _run(_cli() + ["run", "--ephemeral", "--out-dir", str(out), "--run-id", run_id, "--policy-id", "demo", "--policy-path", str(policy), "--", "echo", "1"], cwd=root)
    assert p.returncode == 0
    p = _run(_cli() + ["run", "--ephemeral", "--out-dir", str(out), "--run-id", run_id, "--policy-id", "demo", "--policy-path", str(policy), "--", "echo", "2"], cwd=root)
    assert p.returncode == 0

    mj_path = out / "run_manifest.json"
    mj = json.loads(mj_path.read_text())

    # reorder receipts
    mj["receipts"] = list(reversed(mj["receipts"]))
    mj_path.write_text(json.dumps(mj, indent=2, sort_keys=True))

    trust = tmp_path / "trusted_keys.json"
    trust.write_text(json.dumps({"trusted_key_ids": []}))
    p = _run(_cli() + ["trust", "add", "--pubkey", str(out / "public_key_b64.json"), "--trust", str(trust)], cwd=root)
    assert p.returncode == 0

    p = _run(_cli() + ["verify-manifest", "--manifest", str(mj_path), "--trust", str(trust)], cwd=root)
    assert p.returncode == 2