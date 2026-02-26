# /Users/vikaskumar/Desktop/verifiable-agent-ci/tests/test_cli_receipt.py
import json
import subprocess
from pathlib import Path


def test_receipt_tamper_fails(tmp_path: Path):
    out = tmp_path / ".vaci"
    cmd = [
        "python", "-m", "vaci.cli", "run",
        "--ephemeral",
        "--out-dir", str(out),
        "--",
        "python", "-c", "print('hello from vaci')"
    ]
    env = dict(**__import__("os").environ)
    env["PYTHONPATH"] = "src"
    subprocess.check_call(cmd, env=env)

    # tamper receipt
    receipt_path = out / "receipt.json"
    r = json.loads(receipt_path.read_text())
    r["exit_code"] = 123  # mutate
    receipt_path.write_text(json.dumps(r, indent=2, sort_keys=True))

    # verify should fail (exit code 2)
    verify = [
        "python", "-m", "vaci.cli", "verify",
        "--receipt", str(receipt_path),
        "--pubkey", str(out / "public_key_b64.json"),
    ]
    p = subprocess.run(verify, env=env, capture_output=True, text=True)
    assert p.returncode == 2