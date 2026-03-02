from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _run(cmd: list[str], cwd: Path):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)


def _cli():
    return ["python", "-m", "vaci.cli"]


def test_bundle_roundtrip_verify_ok(tmp_path: Path):
    root = Path.cwd()
    out = tmp_path / ".vaci"
    out.mkdir(parents=True, exist_ok=True)

    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 1, "allow": ["echo"]}))

    keyfile = tmp_path / "gw.key"
    p = _run(_cli() + ["keygen", "--out", str(keyfile)], cwd=root)
    assert p.returncode == 0, p.stderr

    run_id = "bundle_run_1"
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
            "hello",
        ],
        cwd=root,
    )
    assert p.returncode == 0, p.stderr

    # trust
    trust = tmp_path / "trusted_keys.json"
    trust.write_text(json.dumps({"trusted_key_ids": []}))
    p = _run(_cli() + ["trust", "add", "--pubkey", str(out / "public_key_b64.json"), "--trust", str(trust)], cwd=root)
    assert p.returncode == 0, p.stderr

    # finalize
    p = _run(_cli() + ["finalize", "--manifest", str(out / "run_manifest.json"), "--keyfile", str(keyfile)], cwd=root)
    assert p.returncode == 0, p.stderr

    # bundle
    bundle = tmp_path / "run_bundle.tgz"
    p = _run(_cli() + ["bundle", "--manifest", str(out / "run_manifest.json"), "--out", str(bundle), "--policy-path", str(policy)], cwd=root)
    assert p.returncode == 0, p.stderr
    assert bundle.exists()

    # verify bundle
    p = _run(_cli() + ["verify-bundle", "--bundle", str(bundle), "--trust", str(trust), "--require-finalized"], cwd=root)
    assert p.returncode == 0, (p.stdout or "") + (p.stderr or "")


def test_bundle_tamper_fails(tmp_path: Path):
    root = Path.cwd()
    out = tmp_path / ".vaci"
    out.mkdir(parents=True, exist_ok=True)

    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 1, "allow": ["echo"]}))

    keyfile = tmp_path / "gw.key"
    p = _run(_cli() + ["keygen", "--out", str(keyfile)], cwd=root)
    assert p.returncode == 0, p.stderr

    run_id = "bundle_run_2"
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
            "hello",
        ],
        cwd=root,
    )
    assert p.returncode == 0, p.stderr

    trust = tmp_path / "trusted_keys.json"
    trust.write_text(json.dumps({"trusted_key_ids": []}))
    p = _run(_cli() + ["trust", "add", "--pubkey", str(out / "public_key_b64.json"), "--trust", str(trust)], cwd=root)
    assert p.returncode == 0, p.stderr

    p = _run(_cli() + ["finalize", "--manifest", str(out / "run_manifest.json"), "--keyfile", str(keyfile)], cwd=root)
    assert p.returncode == 0, p.stderr

    bundle = tmp_path / "run_bundle.tgz"
    p = _run(_cli() + ["bundle", "--manifest", str(out / "run_manifest.json"), "--out", str(bundle)], cwd=root)
    assert p.returncode == 0, p.stderr

    # Tamper: extract, modify a receipt, re-tar
    import tarfile, tempfile

    with tempfile.TemporaryDirectory(prefix="vaci_tamper_") as td:
        td = Path(td)
        with tarfile.open(bundle, "r:gz") as tf:
            tf.extractall(td)

        # modify a receipt file
        receipts = list(td.glob("receipt_*.json"))
        assert receipts
        r = receipts[0]
        j = json.loads(r.read_text())
        j["stdout_b64"] = j["stdout_b64"][:-2] + "AA"  # small tamper
        r.write_text(json.dumps(j, indent=2, sort_keys=True))

        tampered = tmp_path / "run_bundle_tampered.tgz"
        with tarfile.open(tampered, "w:gz") as tf:
            for f in td.iterdir():
                tf.add(f, arcname=f.name)

    p = _run(_cli() + ["verify-bundle", "--bundle", str(tampered), "--trust", str(trust)], cwd=root)
    assert p.returncode != 0