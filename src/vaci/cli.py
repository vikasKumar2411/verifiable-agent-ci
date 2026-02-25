from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

from vaci.gateway import LocalGateway, Receipt, verify_receipt


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def cmd_run(args: argparse.Namespace) -> int:
    import base64
    from cryptography.hazmat.primitives import serialization

    gw = LocalGateway.ephemeral()
    receipt = gw.run(args.command, cwd=args.cwd)

    pubkey_bytes = gw.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    out_dir = Path(args.out_dir)
    _write_json(out_dir / "public_key_b64.json", {
        "pubkey_b64": base64.urlsafe_b64encode(pubkey_bytes).decode("ascii").rstrip("=")
    })
    _write_json(out_dir / "receipt.json", receipt.to_dict())
    return 0
def cmd_verify(args: argparse.Namespace) -> int:
    import base64
    from cryptography.hazmat.primitives.asymmetric import ed25519

    receipt_path = Path(args.receipt)
    pubkey_path = Path(args.pubkey)

    rj = _read_json(receipt_path)
    pj = _read_json(pubkey_path)

    pubkey_raw = base64.urlsafe_b64decode(pj["pubkey_b64"] + "==")
    pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_raw)
    sig = rj["signature"]

    receipt = Receipt(
        command=rj["command"],
        cwd=rj["cwd"],
        started_at_ms=rj["started_at_ms"],
        finished_at_ms=rj["finished_at_ms"],
        exit_code=rj["exit_code"],
        stdout_b64=rj["stdout_b64"],
        stderr_b64=rj["stderr_b64"],
        stdout_sha256_b64=rj["stdout_sha256_b64"],
        stderr_sha256_b64=rj["stderr_sha256_b64"],
        signature=__import__("vaci.schema", fromlist=["Signature"]).Signature(**sig),
    )

    ok = verify_receipt(pubkey, receipt)
    if not ok:
        print("FAIL: receipt verification failed", file=sys.stderr)
        return 2

    print("OK: receipt verified", file=sys.stderr)
    return 0

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vaci")
    sp = ap.add_subparsers(dest="cmd", required=True)

    runp = sp.add_parser("run", help="Run a command and emit signed receipt artifacts")
    runp.add_argument("--out-dir", default=".vaci", help="Directory to write receipt artifacts")
    runp.add_argument("--cwd", default=None, help="Working directory")
    runp.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute (use: vaci run -- <cmd>)")
    runp.set_defaults(fn=cmd_run)

    verp = sp.add_parser("verify", help="Verify a receipt artifact")
    verp.add_argument("--receipt", default=".vaci/receipt.json")
    verp.add_argument("--pubkey", default=".vaci/public_key_b64.json")
    verp.set_defaults(fn=cmd_verify)

    args = ap.parse_args(argv)

    if args.cmd == "run":
        # strip leading "--" if present
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        if not args.command:
            ap.error("vaci run requires a command: vaci run -- <cmd>")
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())