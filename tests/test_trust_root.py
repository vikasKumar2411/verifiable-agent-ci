from __future__ import annotations

import json
from pathlib import Path

from vaci.cli import cmd_run, cmd_verify


class Args:  # simple namespace
    pass


def test_verify_fails_when_signer_untrusted(tmp_path: Path, monkeypatch):
    # run -> produces .vaci artifacts in tmp_path
    out_dir = tmp_path / ".vaci"

    a = Args()
    a.out_dir = str(out_dir)
    a.cwd = None
    a.command = ["echo", "hello"]
    assert cmd_run(a) == 0

    # empty trust store
    trust_path = tmp_path / "trusted_keys.json"
    trust_path.write_text(json.dumps({"trusted_key_ids": []}, indent=2) + "\n", encoding="utf-8")

    v = Args()
    v.receipt = str(out_dir / "receipt.json")
    v.pubkey = str(out_dir / "public_key_b64.json")
    v.trust = str(trust_path)

    rc = cmd_verify(v)
    assert rc != 0


def test_verify_passes_when_signer_trusted(tmp_path: Path):
    out_dir = tmp_path / ".vaci"

    a = Args()
    a.out_dir = str(out_dir)
    a.cwd = None
    a.command = ["echo", "hello"]
    assert cmd_run(a) == 0

    receipt = json.loads((out_dir / "receipt.json").read_text(encoding="utf-8"))
    # In our implementation, key_id is either in receipt.signature.key_id or derived from pubkey.
    # Your current receipt doesn't store key_id; cmd_verify derives it from the pubkey, so we just
    # take it from the failure message in practice. But for a proper test, compute it from pubkey.
    import base64, hashlib
    pubj = json.loads((out_dir / "public_key_b64.json").read_text(encoding="utf-8"))
    pub_raw = base64.urlsafe_b64decode(pubj["pubkey_b64"] + "==")
    key_id = hashlib.sha256(pub_raw).hexdigest()

    trust_path = tmp_path / "trusted_keys.json"
    trust_path.write_text(json.dumps({"trusted_key_ids": [key_id]}, indent=2) + "\n", encoding="utf-8")

    v = Args()
    v.receipt = str(out_dir / "receipt.json")
    v.pubkey = str(out_dir / "public_key_b64.json")
    v.trust = str(trust_path)

    rc = cmd_verify(v)
    assert rc == 0