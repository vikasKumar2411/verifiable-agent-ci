import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    r = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(
            "Command failed:\n"
            f"  cmd: {' '.join(cmd)}\n"
            f"  rc: {r.returncode}\n"
            f"  stdout:\n{r.stdout}\n"
            f"  stderr:\n{r.stderr}\n"
        )


def test_verify_manifest_two_receipts(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    policy_path = out_dir / "policy.json"
    trust_path = out_dir / "trusted_keys.json"
    manifest_path = out_dir / "run_manifest.json"
    keyfile_path = out_dir / "gateway_ed25519.key"
    pubkey_path = out_dir / "public_key_b64.json"

    preset = "pr-agent"
    run_id = "t_run"

    # init policy from preset (self-contained)
    _run([sys.executable, "-m", "vaci.cli", "init", "--preset", preset, "--out", str(policy_path), "--force"])

    # keygen + trust
    _run([sys.executable, "-m", "vaci.cli", "keygen", "--out", str(out_dir)])
    _run([sys.executable, "-m", "vaci.cli", "trust", "add", "--pubkey", str(pubkey_path), "--trust", str(trust_path)])

    # run twice (same out_dir/run_id/policy)
    _run(
        [
            sys.executable,
            "-m",
            "vaci.cli",
            "run",
            "--out-dir",
            str(out_dir),
            "--keyfile",
            str(keyfile_path),
            "--run-id",
            run_id,
            "--policy-id",
            preset,
            "--policy-path",
            str(policy_path),
            "--",
            "echo",
            "one",
        ]
    )
    _run(
        [
            sys.executable,
            "-m",
            "vaci.cli",
            "run",
            "--out-dir",
            str(out_dir),
            "--keyfile",
            str(keyfile_path),
            "--run-id",
            run_id,
            "--policy-id",
            preset,
            "--policy-path",
            str(policy_path),
            "--",
            "echo",
            "two",
        ]
    )

    # finalize + verify
    _run([sys.executable, "-m", "vaci.cli", "finalize", "--manifest", str(manifest_path), "--keyfile", str(keyfile_path)])
    _run(
        [
            sys.executable,
            "-m",
            "vaci.cli",
            "verify-manifest",
            "--manifest",
            str(manifest_path),
            "--trust",
            str(trust_path),
            "--policy-path",
            str(policy_path),
        ]
    )