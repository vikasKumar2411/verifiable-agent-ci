import json
import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "vaci.cli"] + cmd,
        cwd=str(cwd),
        text=True,
        capture_output=True,
    )


def test_toolcall_sidecar_binds_and_tamper_detects(tmp_path: Path):
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) keygen
    r = _run(["keygen", "--out", str(out_dir)], cwd=tmp_path)
    assert r.returncode == 0, r.stderr

    # 2) trust add
    pubkey = out_dir / "public_key_b64.json"
    trust = out_dir / "trusted_keys.json"
    r = _run(["trust", "add", "--pubkey", str(pubkey), "--trust", str(trust)], cwd=tmp_path)
    assert r.returncode == 0, r.stderr

    # 3) run with toolcall capture
    # Use fixed call-id so toolcall filename is stable and easy to tamper with.
    run_id = "rid_toolcall"
    call_id = "c1"

    tool_args = {"q": "hello", "k": 3}
    tool_result = {"docs": ["a", "b", "c"], "latency_ms": 12}

    r = _run(
        [
            "run",
            "--out-dir",
            str(out_dir),
            "--keyfile",
            str(out_dir / "gateway_ed25519.key"),
            "--run-id",
            run_id,
            "--policy-id",
            "dev",
            "--call-id",
            call_id,
            "--tool",
            "web.search",
            "--tool-args-json",
            json.dumps(tool_args),
            "--tool-result-json",
            json.dumps(tool_result),
            "--",
            "echo",
            "hello",
        ],
        cwd=tmp_path,
    )
    assert r.returncode == 0, r.stderr

    # 4) verify-manifest should pass (toolcall verified)
    manifest = out_dir / "run_manifest.json"
    r = _run(["verify-manifest", "--manifest", str(manifest), "--trust", str(trust)], cwd=tmp_path)
    assert r.returncode == 0, r.stderr

    # 5) tamper toolcall file and verify-manifest must fail
    toolcall_path = out_dir / f"toolcall_{call_id}.json"
    assert toolcall_path.exists()
    tcj = json.loads(toolcall_path.read_text(encoding="utf-8"))
    # mutate args
    tcj["args"]["k"] = 999
    toolcall_path.write_text(json.dumps(tcj, indent=2, sort_keys=True), encoding="utf-8")

    r = _run(["verify-manifest", "--manifest", str(manifest), "--trust", str(trust)], cwd=tmp_path)
    assert r.returncode != 0, "expected tamper detection to fail verify-manifest"