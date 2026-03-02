# tests/test_verify_manifest_strict.py
import os
import subprocess
import sys
from pathlib import Path


def run(cmd, *, env=None, cwd=None):
    """
    Run a command and capture stdout/stderr for assertions.
    """
    return subprocess.run(cmd, text=True, capture_output=True, env=env, cwd=cwd)


def _clean_env():
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


def _parse_exports(stdout: str) -> dict:
    exports = {}
    for ln in stdout.splitlines():
        ln = ln.strip()
        if ln.startswith("export ") and "=" in ln:
            k, v = ln.split("=", 1)
            key = k.replace("export ", "").strip()
            val = v.split("=", 1)[-1].strip().strip("'\"")
            exports[key] = val
    return exports


def test_verify_manifest_enforce_policy_fails_on_denied(tmp_path: Path):
    env = _clean_env()

    # Create a session dir with preset policy + keys + trust store
    p = run(
        [
            sys.executable,
            "-m",
            "vaci.cli",
            "session",
            "--preset",
            "pr-agent",
            "--base-dir",
            str(tmp_path),
        ],
        env=env,
    )
    assert p.returncode == 0, p.stderr

    exports = _parse_exports(p.stdout)
    assert "VACI_OUT_DIR" in exports, p.stdout

    sess_dir = Path(exports["VACI_OUT_DIR"])
    keyfile = sess_dir / "gateway_ed25519.key"
    trust = sess_dir / "trusted_keys.json"
    policy = sess_dir / "policy.json"
    manifest = sess_dir / "run_manifest.json"

    assert keyfile.exists()
    assert trust.exists()
    assert policy.exists()

    # Allowed command
    p1 = run(
        [
            sys.executable,
            "-m",
            "vaci.cli",
            "run",
            "--out-dir",
            str(sess_dir),
            "--keyfile",
            str(keyfile),
            "--run-id",
            "t1",
            "--policy-id",
            "pr-agent",
            "--policy-path",
            str(policy),
            "--",
            "echo",
            "hello",
        ],
        env=env,
    )
    assert p1.returncode == 0, p1.stderr

    # Denied command: use a reliably-present tool on macOS/Linux (curl),
    # otherwise fall back to wget if curl is missing.
    deny_cmd = ["curl", "--version"]
    which_curl = run(["which", "curl"], env=env)
    if which_curl.returncode != 0:
        deny_cmd = ["wget", "--version"]

    p2 = run(
        [
            sys.executable,
            "-m",
            "vaci.cli",
            "run",
            "--out-dir",
            str(sess_dir),
            "--keyfile",
            str(keyfile),
            "--run-id",
            "t1",
            "--policy-id",
            "pr-agent",
            "--policy-path",
            str(policy),
            "--",
            *deny_cmd,
        ],
        env=env,
    )
    # run should still return 0 because denial is recorded as a receipt
    assert p2.returncode == 0, p2.stderr

    # Default verify should pass (crypto + hashes only)
    pv = run(
        [
            sys.executable,
            "-m",
            "vaci.cli",
            "verify-manifest",
            "--manifest",
            str(manifest),
            "--trust",
            str(trust),
        ],
        env=env,
    )
    assert pv.returncode == 0, (pv.stdout or "") + (pv.stderr or "")

    # Enforce-policy should fail
    ps = run(
        [
            sys.executable,
            "-m",
            "vaci.cli",
            "verify-manifest",
            "--manifest",
            str(manifest),
            "--trust",
            str(trust),
            "--enforce-policy",
        ],
        env=env,
    )
    assert ps.returncode != 0, "Expected strict verify to fail when a denied receipt exists"
    combined = (ps.stderr + ps.stdout).lower()
    assert ("denied" in combined) or ("deny" in combined), combined