from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


def _run(cmd: list[str], cwd: Path) -> None:
    """
    Run a command with nice errors for debugging.
    """
    r = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        env={
            **os.environ,
            # make git commits work in CI without global config
            "GIT_AUTHOR_NAME": os.environ.get("GIT_AUTHOR_NAME", "Test User"),
            "GIT_AUTHOR_EMAIL": os.environ.get("GIT_AUTHOR_EMAIL", "test@example.com"),
            "GIT_COMMITTER_NAME": os.environ.get("GIT_COMMITTER_NAME", "Test User"),
            "GIT_COMMITTER_EMAIL": os.environ.get("GIT_COMMITTER_EMAIL", "test@example.com"),
        },
    )
    if r.returncode != 0:
        raise AssertionError(
            "Command failed:\n"
            f"  cmd: {' '.join(cmd)}\n"
            f"  cwd: {cwd}\n"
            f"  rc:  {r.returncode}\n"
            f"  stdout:\n{r.stdout}\n"
            f"  stderr:\n{r.stderr}\n"
        )


def _read_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _init_git_repo(repo: Path) -> None:
    _run(["git", "init"], cwd=repo)
    # also set local config explicitly (belt  suspenders)
    _run(["git", "config", "user.name", "Test User"], cwd=repo)
    _run(["git", "config", "user.email", "test@example.com"], cwd=repo)


def _commit_all(repo: Path, msg: str = "commit") -> None:
    _run(["git", "add", "-A"], cwd=repo)
    _run(["git", "commit", "-m", msg], cwd=repo)


@pytest.mark.parametrize("changed_mode", ["unstaged", "staged"])
def test_attest_git_changed_emits_files_sidecar_and_verifies(tmp_path: Path, changed_mode: str) -> None:
    """
    Ensures:
      - `vaci run --attest-git-changed` writes files_<call_id>.json
      - entry in run_manifest.json binds files_path/files_sha256/files_record_sha256
      - `vaci verify-manifest` succeeds and deep-checks files_record_sha256
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    # Create  commit a file
    (repo / "a.txt").write_text("hello\n", encoding="utf-8")
    _commit_all(repo, "initial")

    # Modify it (unstaged or staged)
    (repo / "a.txt").write_text("hello world\n", encoding="utf-8")
    if changed_mode == "staged":
        _run(["git", "add", "a.txt"], cwd=repo)

    out_dir = repo / ".vaci"
    out_dir.mkdir(parents=True, exist_ok=True)

    # keygen
    _run(["python", "-m", "vaci.cli", "keygen", "--out", str(out_dir)], cwd=repo)
    keyfile = out_dir / "gateway_ed25519.key"
    assert keyfile.exists()

    # trust add
    _run(
        [
            "python",
            "-m",
            "vaci.cli",
            "trust",
            "add",
            "--pubkey",
            str(out_dir / "public_key_b64.json"),
            "--trust",
            str(out_dir / "trusted_keys.json"),
        ],
        cwd=repo,
    )

    # run with file attestation
    _run(
        [
            "python",
            "-m",
            "vaci.cli",
            "run",
            "--out-dir",
            str(out_dir),
            "--keyfile",
            str(keyfile),
            "--run-id",
            "r1",
            "--policy-id",
            "demo",
            "--attest-git-changed",
            "--",
            "echo",
            "hi",
        ],
        cwd=repo,
    )

    manifest = out_dir / "run_manifest.json"
    assert manifest.exists()
    mj = _read_json(manifest)

    assert "receipts" in mj and isinstance(mj["receipts"], list) and mj["receipts"], "manifest missing receipts"
    entry = mj["receipts"][-1]

    # bound fields must exist
    assert isinstance(entry.get("files_path"), str) and entry["files_path"]
    assert isinstance(entry.get("files_sha256"), str) and entry["files_sha256"]
    assert isinstance(entry.get("files_record_sha256"), str) and entry["files_record_sha256"]

    sidecar = out_dir / entry["files_path"]
    assert sidecar.exists(), "files sidecar referenced by manifest does not exist"
    fj = _read_json(sidecar)

    assert fj.get("mode") in ("git_changed", "mixed", "path")
    assert isinstance(fj.get("base_dir"), str) and fj["base_dir"]
    assert isinstance(fj.get("files"), list)

    # sidecar should include the modified file
    paths = [r.get("path") for r in fj["files"] if isinstance(r, dict)]
    assert "a.txt" in paths, f"expected a.txt in sidecar paths, got: {paths}"

    # verify-manifest should pass (includes deep-check)
    _run(
        [
            "python",
            "-m",
            "vaci.cli",
            "verify-manifest",
            "--manifest",
            str(manifest),
            "--trust",
            str(out_dir / "trusted_keys.json"),
        ],
        cwd=repo,
    )


def test_attest_path_emits_files_sidecar_and_verifies(tmp_path: Path) -> None:
    """
    Ensures:
      - `vaci run --attest-path <dir>` hashes all files under that dir
      - verification succeeds
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    # Create a small artifact directory
    artifacts = repo / "artifacts"
    artifacts.mkdir()
    (artifacts / "x.bin").write_bytes(b"\x00\x01\x02\x03")
    (artifacts / "y.txt").write_text("y\n", encoding="utf-8")

    # Commit something so git repo is valid (attest-path does not require changes, but git root usage is fine)
    (repo / "README.md").write_text("repo\n", encoding="utf-8")
    _commit_all(repo, "initial")

    out_dir = repo / ".vaci"
    out_dir.mkdir(parents=True, exist_ok=True)

    _run(["python", "-m", "vaci.cli", "keygen", "--out", str(out_dir)], cwd=repo)
    keyfile = out_dir / "gateway_ed25519.key"

    _run(
        [
            "python",
            "-m",
            "vaci.cli",
            "trust",
            "add",
            "--pubkey",
            str(out_dir / "public_key_b64.json"),
            "--trust",
            str(out_dir / "trusted_keys.json"),
        ],
        cwd=repo,
    )

    _run(
        [
            "python",
            "-m",
            "vaci.cli",
            "run",
            "--out-dir",
            str(out_dir),
            "--keyfile",
            str(keyfile),
            "--run-id",
            "r2",
            "--policy-id",
            "demo",
            "--attest-path",
            str(artifacts),
            "--",
            "echo",
            "hi",
        ],
        cwd=repo,
    )

    manifest = out_dir / "run_manifest.json"
    mj = _read_json(manifest)
    entry = mj["receipts"][-1]

    sidecar = out_dir / entry["files_path"]
    fj = _read_json(sidecar)
    paths = sorted([r.get("path") for r in fj["files"] if isinstance(r, dict)])

    # paths should include both files (relative to base_dir when possible)
    assert any(p.endswith("artifacts/x.bin") or p == "artifacts/x.bin" for p in paths), paths
    assert any(p.endswith("artifacts/y.txt") or p == "artifacts/y.txt" for p in paths), paths

    _run(
        [
            "python",
            "-m",
            "vaci.cli",
            "verify-manifest",
            "--manifest",
            str(manifest),
            "--trust",
            str(out_dir / "trusted_keys.json"),
        ],
        cwd=repo,
    )