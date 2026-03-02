import subprocess
import sys
from pathlib import Path


def test_session_prints_exports_and_creates_files(tmp_path: Path):
    base_dir = tmp_path / "sessions"

    cmd = [
        sys.executable,
        "-m",
        "vaci.cli",
        "session",
        "--preset",
        "pr-agent",
        "--base-dir",
        str(base_dir),
    ]

    p = subprocess.run(cmd, text=True, capture_output=True)
    assert p.returncode == 0, p.stderr

    out_lines = [ln.strip() for ln in p.stdout.splitlines() if ln.strip()]
    exports = {}
    for ln in out_lines:
        if ln.startswith("export ") and "=" in ln:
            k, v = ln.split("=", 1)
            exports[k.replace("export ", "").strip()] = v.strip().strip("'\"")

    assert "VACI_OUT_DIR" in exports
    out_dir = Path(exports["VACI_OUT_DIR"])

    assert out_dir.exists()
    assert (out_dir / "gateway_ed25519.key").exists()
    assert (out_dir / "public_key_b64.json").exists()
    assert (out_dir / "trusted_keys.json").exists()
    assert (out_dir / "policy.json").exists()