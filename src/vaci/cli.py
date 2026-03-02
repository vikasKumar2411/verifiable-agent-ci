# /Users/vikaskumar/Desktop/verifiable-agent-ci/src/vaci/cli.py
from __future__ import annotations
from dataclasses import dataclass

import subprocess
import argparse
import base64
import datetime
import hashlib
import json
import os
import shlex
import sys
import time
from pathlib import Path
from typing import Any, Dict

from vaci.trust import TrustError, assert_trusted_signer, key_id_from_receipt_json
from vaci.gateway import LocalGateway, Receipt, verify_receipt, sign_manifest
from vaci.presets import PresetNotFoundError, list_presets, load_preset

def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def _read_json_str(s: str) -> Any:
    try:
        return json.loads(s)
    except Exception as e:
        raise ValueError(f"invalid JSON: {e}")

@dataclass
class ToolcallInputs:
    tool: str
    args: Any
    result: Any
    toolcall_path: Path | None = None

def _load_json_input(path: str | None, inline_json: str | None, label: str) -> Any:
    """
    Load JSON from either a file path or an inline JSON string. Exactly one may be provided.
    If neither provided, returns None.
    """
    if path and inline_json:
        raise ValueError(f"provide either --{label} or --{label}-json, not both")
    if path:
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = (Path.cwd() / p).resolve()
        if not p.exists():
            raise FileNotFoundError(str(p))
        return _read_json(p)
    if inline_json:
        return _read_json_str(inline_json)
    return None

def _collect_toolcall_inputs(args: argparse.Namespace) -> ToolcallInputs | None:
    """
    Return ToolcallInputs if toolcall flags were provided, else None.
    Supports:
      - --tool  (--tool-args/--tool-args-json)  (--tool-result/--tool-result-json)
      - OR --toolcall-path (prebuilt toolcall JSON containing {tool,args,result})
    """
    toolcall_path = getattr(args, "toolcall_path", None)
    tool = getattr(args, "tool", None)
    if toolcall_path:
        # prebuilt file path mode
        p = Path(toolcall_path).expanduser()
        if not p.is_absolute():
            p = (Path.cwd() / p).resolve()
        tcj = _read_json(p)
        t = tcj.get("tool")
        if not isinstance(t, str) or not t:
            raise ValueError("toolcall file missing 'tool'")
        if "args" not in tcj or "result" not in tcj:
            raise ValueError("toolcall file missing 'args' or 'result'")
        return ToolcallInputs(tool=t, args=tcj.get("args"), result=tcj.get("result"), toolcall_path=p)

    if not tool:
        return None

    args_j = _load_json_input(getattr(args, "tool_args", None), getattr(args, "tool_args_json", None), "tool-args")
    result_j = _load_json_input(getattr(args, "tool_result", None), getattr(args, "tool_result_json", None), "tool-result")
    if args_j is None or result_j is None:
        raise ValueError("when using --tool, you must provide both tool args and tool result")
    return ToolcallInputs(tool=tool, args=args_j, result=result_j, toolcall_path=None)

def _iter_files_under(root: Path) -> list[Path]:
    """
    Return all regular files under root (deterministic order).
    """
    root = root.resolve()
    if root.is_file():
        return [root]
    if not root.exists():
        raise FileNotFoundError(str(root))
    out: list[Path] = []
    for p in root.rglob("*"):
        try:
            if p.is_file():
                out.append(p.resolve())
        except Exception:
            # ignore broken symlinks / permission issues
            continue
    out.sort(key=lambda x: str(x))
    return out


def _rel_or_abs(p: Path, base: Path) -> str:
    """
    Prefer a clean relative path when possible; otherwise return absolute string.
    """
    try:
        rp = p.resolve().relative_to(base.resolve())
        return str(rp)
    except Exception:
        return str(p.resolve())


def _file_record(p: Path, base_dir: Path) -> Dict[str, Any]:
    """
    Record a single file digestsize. Path is relative-to-base when possible.
    """
    p = p.resolve()
    try:
        st = p.stat()
        size = int(st.st_size)
    except Exception:
        size = None
    rec: Dict[str, Any] = {
        "path": _rel_or_abs(p, base_dir),
        "sha256": _sha256_file(p),
    }
    if size is not None:
        rec["size_bytes"] = size
    return rec


def _git_root(cwd: Path | None = None) -> Path:
    """
    Return git repo root. Raises on failure.
    """
    cwd_s = str(cwd or Path.cwd())
    try:
        top = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True, cwd=cwd_s).strip()
        return Path(top).resolve()
    except Exception as e:
        raise RuntimeError(f"not a git repo (or git unavailable): {e}")


def _collect_git_changed_files(repo_root: Path) -> list[Path]:
    """
    Changed (uncommitted) files from `git diff --name-only` plus staged from `--cached`.
    Returns absolute Paths, de-duped, deterministic order.
    """
    names: list[str] = []
    try:
        a = subprocess.check_output(["git", "diff", "--name-only"], text=True, cwd=str(repo_root)).splitlines()
        names.extend([x.strip() for x in a if x.strip()])
    except Exception:
        pass
    try:
        b = subprocess.check_output(["git", "diff", "--name-only", "--cached"], text=True, cwd=str(repo_root)).splitlines()
        names.extend([x.strip() for x in b if x.strip()])
    except Exception:
        pass

    # de-dupe while keeping deterministic order
    seen = set()
    out: list[Path] = []
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        out.append((repo_root / n).resolve())
    out.sort(key=lambda x: str(x))
    return out


def _ensure_gitignore_has_vaci(gitignore_path: Path) -> None:
    """
    Add ".vaci/" to .gitignore if missing (idempotent).
    """
    line = ".vaci/"
    if gitignore_path.exists():
        txt = gitignore_path.read_text(encoding="utf-8")
        lines = [l.strip() for l in txt.splitlines()]
        if line in lines:
            return
        # append with newline
        if not txt.endswith("\n"):
            txt = "\n"
        txt += line + "\n"
        gitignore_path.write_text(txt, encoding="utf-8")
    else:
        gitignore_path.write_text(line + "\n", encoding="utf-8")

def _safe_timestamp() -> str:
    # filesystem-friendly timestamp
    return datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")

def _choose_demo_dir(base: str = ".vaci/demo_runs") -> Path:
    base_dir = Path(base).expanduser()
    if not base_dir.is_absolute():
        base_dir = (Path.cwd() / base_dir).resolve()
    run_id = f"demo_{_safe_timestamp()}_{os.getpid()}"
    return base_dir / run_id

def cmd_init(args: argparse.Namespace) -> int:
    """
    Initialize a repo-local VACI policy file from a built-in preset.
    """
    preset = args.preset
    out_path = Path(args.out).expanduser()
    if not out_path.is_absolute():
        out_path = (Path.cwd() / out_path).resolve()

    try:
        policy_obj = load_preset(preset)
    except PresetNotFoundError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"FAIL: could not load preset '{preset}': {e}", file=sys.stderr)
        return 2

    if out_path.exists() and not args.force:
        print(f"FAIL: policy already exists: {out_path}", file=sys.stderr)
        print("Hint: re-run with --force to overwrite.", file=sys.stderr)
        return 2

    _write_json(out_path, policy_obj)
    print(f"OK: wrote policy preset '{preset}' to {out_path}", file=sys.stderr)

    if getattr(args, "gitignore", False):
        gi = Path(args.gitignore_path or ".gitignore").expanduser()
        if not gi.is_absolute():
            gi = (Path.cwd() / gi).resolve()
        _ensure_gitignore_has_vaci(gi)
        print(f"OK: updated .gitignore: {gi}", file=sys.stderr)

    print("\nNext:", file=sys.stderr)
    print(f"  vaci demo --preset {preset}", file=sys.stderr)
    return 0

def cmd_demo(args: argparse.Namespace) -> int:
    """
    Run a deterministic end-to-end demo:
      - keygen  trust add in a fresh demo run dir
      - one allowed command
      - one denied command
      - finalize  verify manifest
    """

    preset = args.preset
    try:
        _ = load_preset(preset)  # validate preset exists early
    except PresetNotFoundError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"FAIL: could not load preset '{preset}': {e}", file=sys.stderr)
        return 2

    demo_dir = Path(args.out_dir).expanduser() if args.out_dir else _choose_demo_dir()
    if not demo_dir.is_absolute():
        demo_dir = (Path.cwd() / demo_dir).resolve()
    demo_dir.mkdir(parents=True, exist_ok=True)

    keyfile = demo_dir / "gateway_ed25519.key"
    pubkey = demo_dir / "public_key_b64.json"
    trust = demo_dir / "trusted_keys.json"
    manifest = demo_dir / "run_manifest.json"

    # We want an explicit run_id so cmd_run can append safely.
    run_id = args.run_id or demo_dir.name

    # Ensure policy file exists at expected path; if missing, write it into demo_dir
    # (demo should be self-contained).
    policy_path = Path(args.policy_path).expanduser() if args.policy_path else (demo_dir / "policy.json")
    if not policy_path.is_absolute():
        policy_path = (Path.cwd() / policy_path).resolve()
    if not policy_path.exists():
        policy_obj = load_preset(preset)
        _write_json(policy_path, policy_obj)

    def _run_cli(argv: list[str]) -> int:
        # Call via python -m vaci.cli to avoid relying on console_script resolution.
        cmd = [sys.executable, "-m", "vaci.cli"] + argv
        if args.verbose:
            print("RUN:", " ".join(cmd), file=sys.stderr)
        return subprocess.call(cmd)

    # 1) keygen
    rc = _run_cli(["keygen", "--out", str(demo_dir)])
    if rc != 0:
        print("FAIL: keygen failed", file=sys.stderr)
        return rc

    # 2) trust add
    rc = _run_cli(["trust", "add", "--pubkey", str(pubkey), "--trust", str(trust)])
    if rc != 0:
        print("FAIL: trust add failed", file=sys.stderr)
        return rc

    # 3) allowed command (echo)
    rc = _run_cli(
        [
            "run",
            "--out-dir",
            str(demo_dir),
            "--keyfile",
            str(keyfile),
            "--run-id",
            run_id,
            "--policy-id",
            preset,
            "--policy-path",
            str(policy_path),
            "--",
            "echo",
            "hello",
        ]
    )
    if rc != 0:
        print("FAIL: allowed run failed", file=sys.stderr)
        return rc

    # 4) denied command (curl) - if curl is missing on the system, fall back to wget.
    deny_cmd = ["curl", "--version"]
    try:
        subprocess.check_output(["which", "curl"], text=True).strip()
    except Exception:
        deny_cmd = ["wget", "--version"]

    rc = _run_cli(
        [
            "run",
            "--out-dir",
            str(demo_dir),
            "--keyfile",
            str(keyfile),
            "--run-id",
            run_id,
            "--policy-id",
            preset,
            "--policy-path",
            str(policy_path),
            "--",
        ] +
         deny_cmd
    )
    # If policy works, cmd_run returns 0 (it records a denied receipt). Any nonzero is unexpected.
    if rc != 0:
        print("FAIL: denied run failed unexpectedly (expected policy denial receipt)", file=sys.stderr)
        return rc

    # 5) finalize manifest
    rc = _run_cli(["finalize", "--manifest", str(manifest), "--keyfile", str(keyfile)])
    if rc != 0:
        print("FAIL: finalize failed", file=sys.stderr)
        return rc

    # 6) verify manifest (default: crypto + hashes + trust + integrity; policy binding check is OK)
    rc = _run_cli(["verify-manifest", "--manifest", str(manifest), "--trust", str(trust), "--policy-path", str(policy_path)])
    if rc != 0:
        print("FAIL: verify-manifest failed", file=sys.stderr)
        return rc

    # 7) summary
    print("\n✅ VACI demo completed", file=sys.stderr)
    print(f"  preset:   {preset}", file=sys.stderr)
    print(f"  run_id:   {run_id}", file=sys.stderr)
    print(f"  out_dir:  {demo_dir}", file=sys.stderr)
    print(f"  manifest: {manifest}", file=sys.stderr)
    print(f"  trust:    {trust}", file=sys.stderr)
    print("\nNext ideas:", file=sys.stderr)
    print(f"  vaci verify-manifest --manifest {manifest} --trust {trust}", file=sys.stderr)
    print(f"  ls -la {demo_dir}", file=sys.stderr)
    return 0

def cmd_session(args: argparse.Namespace) -> int:
    """
    Create a reusable VACI session directory and print env exports.

    Creates:
      - <out_dir>/gateway_ed25519.key
      - <out_dir>/public_key_b64.json
      - <out_dir>/trusted_keys.json (includes generated key_id)
      - <out_dir>/policy.json (from preset)

    Prints (stdout; safe for eval):
      export VACI_OUT_DIR=...
      export VACI_KEYFILE=...
      export VACI_POLICY_PATH=...
      export VACI_POLICY_ID=...
      export VACI_RUN_ID=...
      export VACI_TRUST=...
    """
    import subprocess
    import uuid

    preset = args.preset
    try:
        policy_obj = load_preset(preset)
    except PresetNotFoundError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"FAIL: could not load preset '{preset}': {e}", file=sys.stderr)
        return 2

    run_id = args.run_id or f"session_{_safe_timestamp()}_{os.getpid()}_{uuid.uuid4().hex[:8]}"

    base = Path(args.base_dir or ".vaci/sessions").expanduser()
    if not base.is_absolute():
        base = (Path.cwd() / base).resolve()

    out_dir = base / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    keyfile = out_dir / "gateway_ed25519.key"
    pubkey = out_dir / "public_key_b64.json"
    trust = out_dir / "trusted_keys.json"
    policy_path = out_dir / "policy.json"

    # Write policy
    _write_json(policy_path, policy_obj)

    # keygen
    rc = subprocess.call([sys.executable, "-m", "vaci.cli", "keygen", "--out", str(out_dir)])
    if rc != 0:
        print("FAIL: keygen failed", file=sys.stderr)
        return rc

    # trust add
    rc = subprocess.call(
        [sys.executable, "-m", "vaci.cli", "trust", "add", "--pubkey", str(pubkey), "--trust", str(trust)]
    )
    if rc != 0:
        print("FAIL: trust add failed", file=sys.stderr)
        return rc

    # Print shell exports (stdout; so eval "$( ... )" works)
    print(f"export VACI_OUT_DIR={shlex.quote(str(out_dir))}")
    print(f"export VACI_KEYFILE={shlex.quote(str(keyfile))}")
    print(f"export VACI_POLICY_PATH={shlex.quote(str(policy_path))}")
    print(f"export VACI_POLICY_ID={shlex.quote(str(preset))}")
    print(f"export VACI_RUN_ID={shlex.quote(str(run_id))}")
    print(f"export VACI_TRUST={shlex.quote(str(trust))}")

    if getattr(args, "print_hint", False):
        print("", file=sys.stderr)
        print("Next:", file=sys.stderr)
        print(f'  eval "$(vaci session --preset {preset})"', file=sys.stderr)
        print("  vaci run -- echo hello", file=sys.stderr)

    return 0

def cmd_bundle(args: argparse.Namespace) -> int:
    """
    Create a portable bundle (.tgz) containing:
      - run_manifest.json (signed)
      - all referenced receipt/pubkey files in receipts[]
      - optional toolcall sidecars (if referenced)
      - optional policy.json (if adjacent to manifest or explicitly provided)
    """
    import tarfile

    manifest_path = Path(args.manifest).expanduser()
    if not manifest_path.is_absolute():
        manifest_path = (Path.cwd() / manifest_path).resolve()

    if not manifest_path.exists():
        print(f"FAIL: manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    out_path = Path(args.out).expanduser()
    if not out_path.is_absolute():
        out_path = (Path.cwd() / out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    mj = _read_json(manifest_path)
    receipts = mj.get("receipts") or []
    if not isinstance(receipts, list) or not receipts:
        print("FAIL: manifest missing receipts[]", file=sys.stderr)
        return 2

    def _abs_from_manifest(rel_or_abs: str) -> Path:
        p = Path(rel_or_abs)
        if p.is_absolute():
            return p
        return (manifest_path.parent / p).resolve()

    files: list[Path] = []
    files.append(manifest_path)

    # referenced artifacts
    for i, e in enumerate(receipts):
        if not isinstance(e, dict):
            print(f"FAIL: receipts[{i}] is not an object", file=sys.stderr)
            return 2

        for k in ("receipt_path", "pubkey_path"):
            if k not in e:
                print(f"FAIL: receipts[{i}] missing {k}", file=sys.stderr)
                return 2

        rp = _abs_from_manifest(e["receipt_path"])
        pp = _abs_from_manifest(e["pubkey_path"])
        if not rp.exists():
            print(f"FAIL: missing receipt file: {rp}", file=sys.stderr)
            return 2
        if not pp.exists():
            print(f"FAIL: missing pubkey file: {pp}", file=sys.stderr)
            return 2
        files.extend([rp, pp])

        # optional toolcall sidecar
        tc = e.get("toolcall_path")
        if tc is not None:
            tp = _abs_from_manifest(tc)
            if not tp.exists():
                print(f"FAIL: manifest references missing toolcall file: {tp}", file=sys.stderr)
                return 2
            files.append(tp)

    # optional files sidecar
    fp_rel = e.get("files_path")
    if fp_rel is not None:
        fp = _abs_from_manifest(fp_rel)
        if not fp.exists():
            print(f"FAIL: manifest references missing files sidecar: {fp}", file=sys.stderr)
            return 2
        files.append(fp)

    # Optional policy inclusion:
    # - if user passes --policy-path, include that file as "policy.json" in the bundle
    # - else, if a sibling policy.json exists next to the manifest, include it
    policy_src = None
    if getattr(args, "policy_path", None):
        policy_src = Path(args.policy_path).expanduser()
        if not policy_src.is_absolute():
            policy_src = (Path.cwd() / policy_src).resolve()
        if not policy_src.exists():
            print(f"FAIL: policy file not found: {policy_src}", file=sys.stderr)
            return 2
    else:
        sibling = (manifest_path.parent / "policy.json")
        if sibling.exists():
            policy_src = sibling.resolve()

    # De-dupe by resolved absolute path
    uniq: list[Path] = []
    seen = set()
    for f in files:
        rf = f.resolve()
        if rf not in seen:
            seen.add(rf)
            uniq.append(rf)

    # Write tar.gz with stable, top-level names
    try:
        with tarfile.open(out_path, "w:gz") as tf:
            # Always write manifest as run_manifest.json at root
            tf.add(manifest_path, arcname="run_manifest.json")

            # Add referenced artifacts using their basenames (unique by call_id)
            for f in uniq:
                if f == manifest_path:
                    continue
                tf.add(f, arcname=f.name)

            # Add policy as policy.json (optional)
            if policy_src is not None:
                tf.add(policy_src, arcname="policy.json")
    except Exception as e:
        print(f"FAIL: could not write bundle: {e}", file=sys.stderr)
        return 2

    print(f"OK: wrote bundle: {out_path}", file=sys.stderr)
    return 0


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    """
    Verify a portable bundle:
      - extracts to a temp dir
      - runs verify-manifest on extracted run_manifest.json
    """
    import tarfile
    import tempfile

    bundle_path = Path(args.bundle).expanduser()
    if not bundle_path.is_absolute():
        bundle_path = (Path.cwd() / bundle_path).resolve()

    if not bundle_path.exists():
        print(f"FAIL: bundle not found: {bundle_path}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="vaci_bundle_") as td:
        out_dir = Path(td)

        # Extract
        try:
            with tarfile.open(bundle_path, "r:gz") as tf:
                tf.extractall(out_dir)
        except Exception as e:
            print(f"FAIL: could not extract bundle: {e}", file=sys.stderr)
            return 2

        manifest = out_dir / "run_manifest.json"
        if not manifest.exists():
            print("FAIL: bundle missing run_manifest.json", file=sys.stderr)
            return 2

        # Reuse cmd_verify_manifest but point manifest to extracted dir.
        # Build a tiny argparse-like object with needed fields.
        class _Args:
            pass

        va = _Args()
        va.manifest = str(manifest)
        va.trust = args.trust
        va.pubkey = getattr(args, "pubkey", None)
        va.require_finalized = bool(getattr(args, "require_finalized", False))
        va.enforce_policy = bool(getattr(args, "enforce_policy", False))

        # policy-path:
        # - if user supplied, use it (recompute sha256 against that file)
        # - else if bundle contains policy.json, use that
        if getattr(args, "policy_path", None):
            va.policy_path = args.policy_path
        else:
            bundled_policy = out_dir / "policy.json"
            va.policy_path = str(bundled_policy) if bundled_policy.exists() else None

        return cmd_verify_manifest(va)


def _now_ms() -> int:
    return int(time.time() * 1000)

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_obj(obj: Any) -> str:
    """
    Hash a JSON-serializable object deterministically (canonical-ish JSON).
    """
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def _compute_policy_sha256(policy_path: str | None) -> str | None:
    if not policy_path:
        return None
    p = Path(policy_path).expanduser()
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    if not p.exists():
        raise FileNotFoundError(str(p))
    return _sha256_file(p)

def _write_gateway_keyfile(path: Path, gw: LocalGateway) -> None:
    """
    Persist a gateway keyfile in the same format as cmd_keygen produces,
    so LocalGateway.from_keyfile() can reload it.
    """
    import base64 as _b64
    from cryptography.hazmat.primitives import serialization

    priv = getattr(gw, "private_key_bytes", None)
    pub = getattr(gw, "public_key", None)

    # Some implementations may expose these as callables/properties
    if callable(priv):
        priv = priv()
    if callable(pub):
        pub = pub()

    # ---- coerce private key to raw bytes ----
    if hasattr(priv, "private_bytes"):
        priv = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    elif isinstance(priv, str):
        # allow urlsafe b64 (no padding) just in case
        priv = _b64.urlsafe_b64decode(priv + "==")

    # ---- coerce public key to raw bytes ----
    if hasattr(pub, "public_bytes"):
        pub = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    elif isinstance(pub, str):
        pub = _b64.urlsafe_b64decode(pub  + "==")

    if not isinstance(priv, (bytes, bytearray)) or not isinstance(pub, (bytes, bytearray)):
        raise TypeError("LocalGateway must expose raw private/public key bytes")

    priv_b = bytes(priv)
    pub_b = bytes(pub)
    key_id = hashlib.sha256(pub_b).hexdigest()

    obj = {
        "kty": "Ed25519",
        "format": "raw",
        "privkey_b64": _b64.urlsafe_b64encode(priv_b).decode("ascii").rstrip("="),
        "pubkey_b64": _b64.urlsafe_b64encode(pub_b).decode("ascii").rstrip("="),
        "key_id": key_id,
    }
    _write_json(path, obj)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def _entry_hash(entry: Dict[str, Any]) -> str:
    """
    Hash an entry excluding its own entry_hash.
    """
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    return _sha256_obj(payload)


def _manifest_payload_from_signed(mj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Take a signed manifest json dict and return the unsigned payload object
    suitable for re-signing (drops signature  manifest_hash).
    """
    payload = dict(mj)
    payload.pop("signature", None)
    payload.pop("manifest_hash", None)
    return payload

def cmd_keygen(args: argparse.Namespace) -> int:
    out_arg = Path(args.out)

    out_is_dir = (
        (out_arg.exists() and out_arg.is_dir())
        or str(args.out).endswith(os.sep)
        or (out_arg.suffix == "")
    )

    if out_is_dir:
        out_dir = out_arg
        out_dir.mkdir(parents=True, exist_ok=True)
        keyfile_path = out_dir / "gateway_ed25519.key"
        pubfile_path = out_dir / "public_key_b64.json"
    else:
        keyfile_path = out_arg
        keyfile_path.parent.mkdir(parents=True, exist_ok=True)
        pubfile_path = keyfile_path.parent / "public_key_b64.json"

    from vaci.crypto import generate_ed25519_keypair

    priv, pub = generate_ed25519_keypair()

    # Support both raw bytes and cryptography key objects
    if hasattr(priv, "private_bytes"):
        from cryptography.hazmat.primitives import serialization

        priv = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    if hasattr(pub, "public_bytes"):
        from cryptography.hazmat.primitives import serialization

        pub = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    if not isinstance(priv, (bytes, bytearray)) or not isinstance(pub, (bytes, bytearray)):
        raise TypeError("generate_ed25519_keypair() must return bytes or key objects convertible to raw bytes")

    priv = bytes(priv)
    pub = bytes(pub)

    key_id = hashlib.sha256(pub).hexdigest()

    obj = {
        "kty": "Ed25519",
        "format": "raw",
        "privkey_b64": base64.urlsafe_b64encode(priv).decode("ascii").rstrip("="),
        "pubkey_b64": base64.urlsafe_b64encode(pub).decode("ascii").rstrip("="),
        "key_id": key_id,
    }

    _write_json(keyfile_path, obj)
    _write_json(pubfile_path, {"pubkey_b64": obj["pubkey_b64"]})

    try:
        os.chmod(keyfile_path, 0o600)
    except Exception:
        pass

    print(f"OK: wrote gateway keyfile to {keyfile_path}", file=sys.stderr)
    print(f"OK: wrote public key to {pubfile_path}", file=sys.stderr)
    print(f"key_id: {key_id}", file=sys.stderr)
    return 0

def cmd_trust_add(args: argparse.Namespace) -> int:
    """
    Add a signer key_id to trusted_keys.json using a public_key_b64.json file.
    """
    pubkey_path = Path(args.pubkey)
    trust_path = Path(args.trust)

    pj = _read_json(pubkey_path)
    pub_b64 = pj.get("pubkey_b64")
    if not isinstance(pub_b64, str) or not pub_b64:
        print("FAIL: pubkey file must contain pubkey_b64", file=sys.stderr)
        return 2

    pub_raw = base64.urlsafe_b64decode(pub_b64 + "==")
    key_id = hashlib.sha256(pub_raw).hexdigest()

    if trust_path.exists():
        tj = _read_json(trust_path)
    else:
        tj = {"trusted_key_ids": []}

    ids = tj.get("trusted_key_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        print('FAIL: trust store must contain {"trusted_key_ids": [..strings..]}', file=sys.stderr)
        return 2

    if key_id not in ids:
        ids.append(key_id)
        tj["trusted_key_ids"] = sorted(set(ids))
        _write_json(trust_path, tj)

    print(f"OK: trusted key_id {key_id}", file=sys.stderr)
    return 0

def cmd_finalize(args: argparse.Namespace) -> int:
    """
    Finalize a run_manifest.json (set finalized=true) and re-sign it.
    After finalization, cmd_run will refuse to append additional receipts.
    """
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"FAIL: manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    # Load gateway key for re-sign
    try:
        gw = LocalGateway.from_keyfile(args.keyfile)
    except FileNotFoundError:
        print(f"FAIL: gateway keyfile not found: {args.keyfile}", file=sys.stderr)
        print("Hint: run: vaci keygen --out .vaci_keys/gateway_ed25519.key", file=sys.stderr)
        return 2

    mj = _read_json(manifest_path)
    payload = _manifest_payload_from_signed(mj)

    if payload.get("finalized") is True:
        print("OK: manifest already finalized", file=sys.stderr)
        return 0

    payload["finalized"] = True
    payload["updated_at_ms"] = _now_ms()

    signed = sign_manifest(gw.private_key_bytes, payload)
    _write_json(manifest_path, signed)

    print(f"OK: manifest finalized: {manifest_path}", file=sys.stderr)
    return 0

def cmd_run(args: argparse.Namespace) -> int:
    import base64 as _b64
    from cryptography.hazmat.primitives import serialization
    import uuid

    # ---- env fallbacks (flags win) ----
    out_dir_str = getattr(args, "out_dir", None) or os.environ.get("VACI_OUT_DIR") or ".vaci"
    out_dir = Path(out_dir_str).expanduser()
    if not out_dir.is_absolute():
        out_dir = (Path.cwd() / out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    run_id = getattr(args, "run_id", None) or os.environ.get("VACI_RUN_ID") or uuid.uuid4().hex
    call_id = getattr(args, "call_id", None) or uuid.uuid4().hex
    policy_id = getattr(args, "policy_id", None) or os.environ.get("VACI_POLICY_ID") or "dev"
    policy_path = getattr(args, "policy_path", None) or os.environ.get("VACI_POLICY_PATH")

    try:
        policy_sha256 = _compute_policy_sha256(policy_path)
    except FileNotFoundError as e:
        print(f"FAIL: policy file not found: {e}", file=sys.stderr)
        return 2

    # Commit 2: persistent gateway by default
    if getattr(args, "ephemeral", False):
        # IMPORTANT: keep ephemeral signer stable across a session (same out_dir),
        # otherwise manifest signature will flip every run and verification fails.
        ephem_keyfile = out_dir / "ephemeral_gateway_ed25519.key"
        if ephem_keyfile.exists():
            gw = LocalGateway.from_keyfile(str(ephem_keyfile))
        else:
            gw = LocalGateway.ephemeral()
            _write_gateway_keyfile(ephem_keyfile, gw)
    else:
        try:
            keyfile = (
                getattr(args, "keyfile", None)
                or os.environ.get("VACI_KEYFILE")
                or ".vaci_keys/gateway_ed25519.key"
            )
            gw = LocalGateway.from_keyfile(keyfile)
        except FileNotFoundError:
            print(f"FAIL: gateway keyfile not found: {keyfile}", file=sys.stderr)
            print("Hint: run: vaci keygen --out .vaci_keys/gateway_ed25519.key", file=sys.stderr)
            return 2

    # ---- V2: enforce policy BEFORE execution ----
    deny_reason = None
    if policy_path:
        try:
            from vaci.core.policy import load_policy, evaluate

            pol = load_policy(policy_path)
            dec = evaluate(pol, args.command, cwd=args.cwd or os.getcwd())
            if not dec.allowed:
                deny_reason = dec.reason
        except Exception as e:
            # Policy read/parse errors are treated as hard fail (safer default)
            print(f"FAIL: policy evaluation error: {e}", file=sys.stderr)
            return 2

    if deny_reason is not None:
        receipt = gw.run_denied(
            args.command,
            cwd=args.cwd,
            run_id=run_id,
            policy_id=policy_id,
            call_id=call_id,
            policy_sha256=policy_sha256,
            deny_reason=deny_reason,
        )
    else:
        receipt = gw.run(
            args.command,
            cwd=args.cwd,
            run_id=run_id,
            policy_id=policy_id,
            call_id=call_id,
            policy_sha256=policy_sha256,
        )

    pk = gw.public_key
    # Support both "raw bytes" or "cryptography key object"
    if hasattr(pk, "public_bytes"):
        pubkey_bytes = pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    else:
        pubkey_bytes = pk

    # Per-call artifacts (session mode)
    receipt_name = f"receipt_{call_id}.json"
    pubkey_name = f"public_key_{call_id}.json"

    pubkey_path = out_dir / pubkey_name
    _write_json(
        pubkey_path,
        {"pubkey_b64": _b64.urlsafe_b64encode(pubkey_bytes).decode("ascii").rstrip("=")},
    )

    receipt_path = out_dir / receipt_name
    _write_json(receipt_path, receipt.to_dict())

    # Back-compat / convenience: also write the "latest" filenames
    _write_json(out_dir / "public_key_b64.json", {"pubkey_b64": _b64.urlsafe_b64encode(pubkey_bytes).decode("ascii").rstrip("=")})
    _write_json(out_dir / "receipt.json", receipt.to_dict())

    # ---- OPTIONAL: toolcall sidecar (agent tooling) ----
     #
     # If provided, emit toolcall_<call_id>.json and bind its hashes into the manifest entry.
     #
    #
    # If provided, emit toolcall_<call_id>.json and bind its hashes into the manifest entry.
    #
    toolcall_rel_name: str | None = None
    toolcall_sha256: str | None = None
    toolcall_record_sha256: str | None = None

    try:
        tcin = _collect_toolcall_inputs(args)
    except FileNotFoundError as e:
        print(f"FAIL: toolcall JSON file not found: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"FAIL: toolcall args error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"FAIL: toolcall processing error: {e}", file=sys.stderr)
        return 2

    if tcin is not None:
        # If caller supplied a prebuilt toolcall file, we still copy it into out_dir with stable name
        toolcall_path = out_dir / f"toolcall_{call_id}.json"
        tc_obj = {
            "tool": tcin.tool,
            "args": tcin.args,
            "result": tcin.result,
        }
        # Optional deep-check helpers (verifier already supports these)
        tc_obj["args_sha256"] = _sha256_obj(tcin.args)
        tc_obj["result_sha256"] = _sha256_obj(tcin.result)
        tc_obj["toolcall_record_sha256"] = _sha256_obj({"tool": tcin.tool, "args": tcin.args, "result": tcin.result})

        # Write canonical toolcall sidecar into out_dir
        _write_json(toolcall_path, tc_obj)

        toolcall_rel_name = toolcall_path.name
        toolcall_sha256 = _sha256_file(toolcall_path)
        toolcall_record_sha256 = tc_obj["toolcall_record_sha256"]


    # ---- OPTIONAL: files sidecar (file attestation) ----
    #
    # Emits files_<call_id>.json and binds its hashes into the manifest entry.
    #
    files_rel_name: str | None = None
    files_sha256: str | None = None
    files_record_sha256: str | None = None

    want_git_changed = bool(getattr(args, "attest_git_changed", False))
    attest_paths = getattr(args, "attest_paths", None) or []
    if want_git_changed or attest_paths:
        try:
            # base_dir:
            # - git_changed => repo root (more stable)
            # - path mode   => cwd (unless we can infer a git root cleanly)
            if want_git_changed:
                base_dir = _git_root()
            else:
                base_dir = Path.cwd().resolve()

            roots: list[str] = []
            file_list: list[Path] = []

            if want_git_changed:
                roots.append("git_changed")
                file_list.extend(_collect_git_changed_files(base_dir))

            for ap in attest_paths:
                p = Path(ap).expanduser()
                if not p.is_absolute():
                    p = (Path.cwd() / p).resolve()
                roots.append(_rel_or_abs(p, base_dir))
                file_list.extend(_iter_files_under(p))

            # de-dupe deterministically
            seen = set()
            uniq: list[Path] = []
            for f in file_list:
                rf = f.resolve()
                if rf in seen:
                    continue
                seen.add(rf)
                uniq.append(rf)
            uniq.sort(key=lambda x: str(x))

            files_obj: Dict[str, Any] = {
                "mode": "git_changed" if want_git_changed and not attest_paths else ("mixed" if want_git_changed else "path"),
                "base_dir": str(base_dir),
                "roots": roots,
                "files": [_file_record(f, base_dir) for f in uniq],
            }
            files_obj["files_record_sha256"] = _sha256_obj(
                {
                    "mode": files_obj["mode"],
                    "base_dir": files_obj["base_dir"],
                    "roots": files_obj["roots"],
                    "files": files_obj["files"],
                }
            )

            files_path = out_dir / f"files_{call_id}.json"
            _write_json(files_path, files_obj)

            files_rel_name = files_path.name
            files_sha256 = _sha256_file(files_path)
            files_record_sha256 = files_obj["files_record_sha256"]
        except FileNotFoundError as e:
            print(f"FAIL: file attestation path not found: {e}", file=sys.stderr)
            return 2
        except RuntimeError as e:
            print(f"FAIL: file attestation error: {e}", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"FAIL: file attestation processing error: {e}", file=sys.stderr)
            return 2


    # ---- NEW: run manifest ----
    import subprocess

    manifest_path = out_dir / "run_manifest.json"

    try:
        git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        git_sha = None


    # Safety: if manifest exists, require explicit run-id (or env VACI_RUN_ID) to append.
    if manifest_path.exists() and not (getattr(args, "run_id", None) or os.environ.get("VACI_RUN_ID")):
        print(
            "FAIL: manifest exists; refusing to append without explicit --run-id (or env VACI_RUN_ID)\n"
            "Hint: either:\n"
            "  - pass --run-id <same as the existing manifest>, or\n"
            "  - start a new session (rm -rf .vaci / use a different --out-dir).",
            file=sys.stderr,
        )
        return 2

    entry = {
        "call_id": call_id,
        "created_at_ms": _now_ms(),
        "receipt_path": receipt_path.name,
        "receipt_sha256": _sha256_file(receipt_path),
        "pubkey_path": pubkey_path.name,
        "pubkey_sha256": _sha256_file(pubkey_path),
        "policy_sha256": policy_sha256,
    }

    if toolcall_rel_name is not None:
        entry["toolcall_path"] = toolcall_rel_name
        entry["toolcall_sha256"] = toolcall_sha256
        entry["toolcall_record_sha256"] = toolcall_record_sha256

    if files_rel_name is not None:
        entry["files_path"] = files_rel_name
        entry["files_sha256"] = files_sha256
        entry["files_record_sha256"] = files_record_sha256

    if manifest_path.exists():
        mj = _read_json(manifest_path)
        payload = _manifest_payload_from_signed(mj)

        # enforce session invariants
        if payload.get("finalized") is True:
            print(
                "FAIL: manifest is finalized; refusing to append\n"
                "Hint: start a new session by:\n"
                "  - removing the out-dir (e.g. rm -rf .vaci), or\n"
                "  - using a different --out-dir, or\n"
                "  - using a new run_id in a fresh directory.",
                file=sys.stderr,
            )
            return 2

        if payload.get("run_id") != run_id:
            print(f"FAIL: run_id mismatch vs existing manifest ({payload.get('run_id')} != {run_id})", file=sys.stderr)
            return 2
        if payload.get("policy_id") != policy_id:
            print(f"FAIL: policy_id mismatch vs existing manifest ({payload.get('policy_id')} != {policy_id})", file=sys.stderr)
            return 2

        if payload.get("policy_sha256") != policy_sha256:
            print("FAIL: policy_sha256 mismatch vs existing manifest", file=sys.stderr)
            print(f"  expected: {payload.get('policy_sha256')}", file=sys.stderr)
            print(f"  got: {policy_sha256}", file=sys.stderr)
            return 2

        receipts = payload.get("receipts")
        if not isinstance(receipts, list):
            print("FAIL: manifest payload receipts must be a list", file=sys.stderr)
            return 2

        # keep created_at_ms stable; bump updated_at_ms
        payload.setdefault("created_at_ms", _now_ms())
        payload["updated_at_ms"] = _now_ms()
        payload.setdefault("finalized", False)
        payload.setdefault("policy_sha256", policy_sha256)

        # preserve git_sha from first creation unless missing
        if payload.get("git_sha") is None:
            payload["git_sha"] = git_sha

        # chain hashes
        prev = receipts[-1].get("entry_hash") if receipts else None
        entry["prev_entry_hash"] = prev
        entry["entry_hash"] = _entry_hash(entry)

        receipts.append(entry)
    else:
        entry["prev_entry_hash"] = None
        entry["entry_hash"] = _entry_hash(entry)
        payload = {
            "run_id": run_id,
            "policy_id": policy_id,
            "git_sha": git_sha,
            "created_at_ms": _now_ms(),
            "updated_at_ms": _now_ms(),
            "finalized": False,
            "policy_sha256": policy_sha256,
            "receipts": [entry],
        }

    signed_manifest = sign_manifest(gw.private_key_bytes, payload)
    _write_json(manifest_path, signed_manifest)
    # --------------------------

    return 0

def cmd_verify_manifest(args: argparse.Namespace) -> int:
    """
    Verify a run_manifest.json:
      1) manifest_hash matches canonical payload (excluding signature; may include or exclude manifest_hash)
      2) signature verifies against the same payload variant
      3) trust-root check passes for signer key_id
      4) referenced files match their sha256
      5) receipts verify cryptographically and are consistent with run_id/policy_id
    """
    import base64 as _b64
    from pathlib import Path

    from vaci.crypto import hashref_sha256_from_obj, verify_obj_ed25519
    from vaci.schema import Signature

    require_finalized = bool(getattr(args, "require_finalized", False))
    manifest_path = Path(args.manifest)
    mj = _read_json(manifest_path)

    enforce_policy = bool(getattr(args, "enforce_policy", False))
    policy_path = getattr(args, "policy_path", None)
    try:
        policy_sha256_expected = _compute_policy_sha256(policy_path) if policy_path else None
    except FileNotFoundError as e:
        print(f"FAIL: policy file not found: {e}", file=sys.stderr)
        return 2

    # -------- helpers --------
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _abs_from_manifest(rel_or_abs: str) -> Path:
        p = Path(rel_or_abs)
        if p.is_absolute():
            return p
        # interpret relative paths as relative to manifest file location
        return (manifest_path.parent / p).resolve()

    # -------- basic shape checks --------
    sig_obj = mj.get("signature")
    if not isinstance(sig_obj, dict):
        print("FAIL: manifest missing signature", file=sys.stderr)
        return 2

    declared_href = mj.get("manifest_hash")
    if not isinstance(declared_href, dict) or declared_href.get("alg") != "sha256":
        print("FAIL: manifest missing manifest_hash", file=sys.stderr)
        return 2

    declared_hex = declared_href.get("hex")
    declared_size = declared_href.get("size_bytes")
    if not isinstance(declared_hex, str) or not isinstance(declared_size, int):
        print("FAIL: manifest_hash must contain {alg, hex(str), size_bytes(int)}", file=sys.stderr)
        return 2

    receipts = mj.get("receipts") or []
    if not isinstance(receipts, list) or not receipts:
        print("FAIL: manifest missing receipts[]", file=sys.stderr)
        return 2

    # -------- find pubkey_path (overrideable) --------
    pubkey_override = getattr(args, "pubkey", None)
    if pubkey_override:
        pubkey_path = Path(pubkey_override)
        if not pubkey_path.is_absolute():
            pubkey_path = (Path.cwd() / pubkey_path).resolve()
    else:
        first = receipts[0]
        if not isinstance(first, dict) or "pubkey_path" not in first:
            print("FAIL: manifest receipts[0] missing pubkey_path", file=sys.stderr)
            return 2
        pubkey_path = _abs_from_manifest(first["pubkey_path"])

    pj = _read_json(pubkey_path)
    pub_b64 = pj.get("pubkey_b64")
    if not isinstance(pub_b64, str) or not pub_b64:
        print("FAIL: pubkey file must contain pubkey_b64", file=sys.stderr)
        return 2

    pubkey_raw = _b64.urlsafe_b64decode(pub_b64 + "==")
    # IMPORTANT: vaci.crypto.verify_obj_ed25519 expects raw pubkey bytes (not a cryptography key object)
    pubkey = pubkey_raw

    # -------- Variant-B only --------
    payload_b = dict(mj)
    payload_b.pop("signature", None)
    payload_b.pop("manifest_hash", None)

    href_b, _ = hashref_sha256_from_obj(payload_b)

    if not (href_b.hex == declared_hex and href_b.size_bytes == declared_size):
        print("FAIL: manifest_hash mismatch (expected Variant-B)", file=sys.stderr)
        return 2

    payload_for_sig = payload_b

    # -------- signature check --------
    try:
        sig = Signature(**sig_obj)
    except Exception as e:
        print(f"FAIL: invalid manifest signature object: {e}", file=sys.stderr)
        return 2

    if not verify_obj_ed25519(pubkey, payload_for_sig, sig):
        print("FAIL: manifest signature verification failed", file=sys.stderr)
        return 2

    # -------- trust root check for signer (enforce allowlist here) --------
    signer_key_id = hashlib.sha256(pubkey_raw).hexdigest()

    trust_path = Path(args.trust).expanduser()
    if not trust_path.is_absolute():
        # interpret relative trust paths relative to current working dir
        trust_path = (Path.cwd() / trust_path).resolve()

    if trust_path.exists():
        try:
            tj = _read_json(trust_path)
        except Exception as e:
            print(f"FAIL: could not read trust store {trust_path}: {e}", file=sys.stderr)
            return 2
    else:
        tj = {"trusted_key_ids": []}

    ids = tj.get("trusted_key_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        print('FAIL: trust store must contain {"trusted_key_ids": [..strings..]}', file=sys.stderr)
        return 2

    if signer_key_id not in set(ids):
        print(f"FAIL: untrusted signer key_id {signer_key_id}", file=sys.stderr)
        print(
            f"Hint: python -m vaci.cli trust add --pubkey .vaci/public_key_b64.json --trust {trust_path}",
            file=sys.stderr,
        )
        return 2

    # -------- verify referenced files + receipts --------
    run_id = mj.get("run_id")
    policy_id = mj.get("policy_id")

    manifest_policy_sha256 = mj.get("policy_sha256")

    if policy_sha256_expected is not None and manifest_policy_sha256 != policy_sha256_expected:
        print("FAIL: manifest policy_sha256 does not match provided policy-path", file=sys.stderr)
        print(f"  expected: {policy_sha256_expected}", file=sys.stderr)
        print(f"  got: {manifest_policy_sha256}", file=sys.stderr)
        return 2

    if require_finalized and mj.get("finalized") is not True:
        print("FAIL: manifest is not finalized", file=sys.stderr)
        print("Hint: run: python -m vaci.cli finalize --manifest <path> --keyfile <key>", file=sys.stderr)
        return 2

    if run_id is not None and not isinstance(run_id, str):
        print("FAIL: manifest run_id must be a string if present", file=sys.stderr)
        return 2
    if policy_id is not None and not isinstance(policy_id, str):
        print("FAIL: manifest policy_id must be a string if present", file=sys.stderr)
        return 2

    # -------- verify receipt entry chain (reorder/delete detection) --------
    prev = None
    for i, e in enumerate(receipts):
        if not isinstance(e, dict):
            print(f"FAIL: receipts[{i}] is not an object", file=sys.stderr)
            return 2
        if e.get("prev_entry_hash") != prev:
            print(f"FAIL: receipt chain broken at index {i}", file=sys.stderr)
            return 2
        eh = e.get("entry_hash")
        if not isinstance(eh, str) or not eh:
            print(f"FAIL: receipts[{i}] missing entry_hash", file=sys.stderr)
            return 2
        calc = _entry_hash(e)
        if calc != eh:
            print(f"FAIL: receipts[{i}] entry_hash mismatch", file=sys.stderr)
            return 2
        prev = eh

    for i, entry in enumerate(receipts):
        if not isinstance(entry, dict):
            print(f"FAIL: receipts[{i}] is not an object", file=sys.stderr)
            return 2

        for k in ("receipt_path", "receipt_sha256", "pubkey_path", "pubkey_sha256", "call_id"):
            if k not in entry:
                print(f"FAIL: receipts[{i}] missing {k}", file=sys.stderr)
                return 2

        rp = _abs_from_manifest(entry["receipt_path"])
        pp = _abs_from_manifest(entry["pubkey_path"])

        # receipt sha
        actual_receipt = _sha256_file(rp)
        expected_receipt = entry.get("receipt_sha256")
        if actual_receipt != expected_receipt:
            print("FAIL: receipt sha256 mismatch", file=sys.stderr)
            print(f"  file: {rp}", file=sys.stderr)
            print(f"  expected: {expected_receipt}", file=sys.stderr)
            print(f"  got: {actual_receipt}", file=sys.stderr)
            return 2

        # pubkey sha
        actual_pubkey = _sha256_file(pp)
        expected_pubkey = entry.get("pubkey_sha256")
        if actual_pubkey != expected_pubkey:
            print("FAIL: pubkey sha256 mismatch", file=sys.stderr)
            print(f"  file: {pp}", file=sys.stderr)
            print(f"  expected: {expected_pubkey}", file=sys.stderr)
            print(f"  got: {actual_pubkey}", file=sys.stderr)
            return 2

        # ---- OPTIONAL: toolcall sidecar binding (agent runner) ----
        toolcall_rel = entry.get("toolcall_path")
        if toolcall_rel is not None:
            if not isinstance(toolcall_rel, str) or not toolcall_rel:
                print(f"FAIL: receipts[{i}] toolcall_path must be a non-empty string", file=sys.stderr)
                return 2

            expected_toolcall = entry.get("toolcall_sha256")
            if not isinstance(expected_toolcall, str) or not expected_toolcall:
                print(f"FAIL: receipts[{i}] missing toolcall_sha256", file=sys.stderr)
                return 2

            tp = _abs_from_manifest(toolcall_rel)
            if not tp.exists():
                print("FAIL: toolcall file missing", file=sys.stderr)
                print(f"  file: {tp}", file=sys.stderr)
                return 2

            actual_toolcall = _sha256_file(tp)
            if actual_toolcall != expected_toolcall:
                print("FAIL: toolcall sha256 mismatch", file=sys.stderr)
                print(f"  file: {tp}", file=sys.stderr)
                print(f"  expected: {expected_toolcall}", file=sys.stderr)
                print(f"  got: {actual_toolcall}", file=sys.stderr)
                return 2
                        # Deep-verify toolcall content (optional but recommended):
            # - ensure required fields exist
            # - verify toolcall_record_sha256 binds (tool,args,result)
            try:
                tcj = _read_json(tp)
            except Exception as e:
                print("FAIL: could not read toolcall json", file=sys.stderr)
                print(f"  file: {tp}", file=sys.stderr)
                print(f"  error: {e}", file=sys.stderr)
                return 2

            tool = tcj.get("tool")
            args_j = tcj.get("args")
            result_j = tcj.get("result")
            if not isinstance(tool, str) or not tool:
                print("FAIL: toolcall missing tool", file=sys.stderr)
                print(f"  file: {tp}", file=sys.stderr)
                return 2
            if "args" not in tcj or "result" not in tcj:
                print("FAIL: toolcall missing args/result", file=sys.stderr)
                print(f"  file: {tp}", file=sys.stderr)
                return 2

            # Verify args_sha256/result_sha256 if present in the toolcall file
            args_sha = tcj.get("args_sha256")
            if args_sha is not None:
                if not isinstance(args_sha, str) or not args_sha:
                    print("FAIL: toolcall args_sha256 must be a non-empty string when present", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    return 2
                calc_args_sha = _sha256_obj(args_j)
                if calc_args_sha != args_sha:
                    print("FAIL: toolcall args_sha256 mismatch", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    print(f"  expected: {args_sha}", file=sys.stderr)
                    print(f"  got: {calc_args_sha}", file=sys.stderr)
                    return 2

            result_sha = tcj.get("result_sha256")
            if result_sha is not None:
                if not isinstance(result_sha, str) or not result_sha:
                    print("FAIL: toolcall result_sha256 must be a non-empty string when present", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    return 2
                calc_result_sha = _sha256_obj(result_j)
                if calc_result_sha != result_sha:
                    print("FAIL: toolcall result_sha256 mismatch", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    print(f"  expected: {result_sha}", file=sys.stderr)
                    print(f"  got: {calc_result_sha}", file=sys.stderr)
                    return 2

            # Verify record binding hash against entry or file (entry wins if present)
            calc_record_sha = _sha256_obj({"tool": tool, "args": args_j, "result": result_j})
            expected_record_sha = entry.get("toolcall_record_sha256") or tcj.get("toolcall_record_sha256")
            if expected_record_sha is not None:
                if not isinstance(expected_record_sha, str) or not expected_record_sha:
                    print("FAIL: toolcall_record_sha256 must be a non-empty string when present", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    return 2
                if calc_record_sha != expected_record_sha:
                    print("FAIL: toolcall_record_sha256 mismatch", file=sys.stderr)
                    print(f"  file: {tp}", file=sys.stderr)
                    print(f"  expected: {expected_record_sha}", file=sys.stderr)
                    print(f"  got: {calc_record_sha}", file=sys.stderr)
                    return 2

                # ---- OPTIONAL: files sidecar binding (file attestation) ----
        files_rel = entry.get("files_path")
        if files_rel is not None:
            if not isinstance(files_rel, str) or not files_rel:
                print(f"FAIL: receipts[{i}] files_path must be a non-empty string", file=sys.stderr)
                return 2

            expected_files_sha = entry.get("files_sha256")
            if not isinstance(expected_files_sha, str) or not expected_files_sha:
                print(f"FAIL: receipts[{i}] missing files_sha256", file=sys.stderr)
                return 2

            fp = _abs_from_manifest(files_rel)
            if not fp.exists():
                print("FAIL: files sidecar missing", file=sys.stderr)
                print(f"  file: {fp}", file=sys.stderr)
                return 2

            actual_files_sha = _sha256_file(fp)
            if actual_files_sha != expected_files_sha:
                print("FAIL: files sidecar sha256 mismatch", file=sys.stderr)
                print(f"  file: {fp}", file=sys.stderr)
                print(f"  expected: {expected_files_sha}", file=sys.stderr)
                print(f"  got: {actual_files_sha}", file=sys.stderr)
                return 2

            # Deep-verify files sidecar content (optional but recommended):
            # - ensure required fields exist
            # - verify files_record_sha256 binds (mode, base_dir, roots, files)
            try:
                fj = _read_json(fp)
            except Exception as e:
                print("FAIL: could not read files sidecar json", file=sys.stderr)
                print(f"  file: {fp}", file=sys.stderr)
                print(f"  error: {e}", file=sys.stderr)
                return 2

            mode = fj.get("mode")
            base_dir = fj.get("base_dir")
            roots = fj.get("roots")
            files_list = fj.get("files")
            if not isinstance(mode, str) or not mode:
                print("FAIL: files sidecar missing mode", file=sys.stderr)
                print(f"  file: {fp}", file=sys.stderr)
                return 2
            if not isinstance(base_dir, str) or not base_dir:
                print("FAIL: files sidecar missing base_dir", file=sys.stderr)
                print(f"  file: {fp}", file=sys.stderr)
                return 2
            if roots is not None and not isinstance(roots, list):
                print("FAIL: files sidecar roots must be a list when present", file=sys.stderr)
                print(f"  file: {fp}", file=sys.stderr)
                return 2
            if not isinstance(files_list, list):
                print("FAIL: files sidecar missing files[]", file=sys.stderr)
                print(f"  file: {fp}", file=sys.stderr)
                return 2

            # Basic schema checks per record
            for j, r in enumerate(files_list):
                if not isinstance(r, dict):
                    print(f"FAIL: files sidecar files[{j}] not an object", file=sys.stderr)
                    print(f"  file: {fp}", file=sys.stderr)
                    return 2
                pth = r.get("path")
                sh = r.get("sha256")
                if not isinstance(pth, str) or not pth:
                    print(f"FAIL: files sidecar files[{j}] missing path", file=sys.stderr)
                    print(f"  file: {fp}", file=sys.stderr)
                    return 2
                if not isinstance(sh, str) or not sh:
                    print(f"FAIL: files sidecar files[{j}] missing sha256", file=sys.stderr)
                    print(f"  file: {fp}", file=sys.stderr)
                    return 2

            calc_files_record = _sha256_obj({"mode": mode, "base_dir": base_dir, "roots": roots or [], "files": files_list})
            expected_files_record = entry.get("files_record_sha256") or fj.get("files_record_sha256")
            if expected_files_record is not None:
                if not isinstance(expected_files_record, str) or not expected_files_record:
                    print("FAIL: files_record_sha256 must be a non-empty string when present", file=sys.stderr)
                    print(f"  file: {fp}", file=sys.stderr)
                    return 2
                if calc_files_record != expected_files_record:
                    print("FAIL: files_record_sha256 mismatch", file=sys.stderr)
                    print(f"  file: {fp}", file=sys.stderr)
                    print(f"  expected: {expected_files_record}", file=sys.stderr)
                    print(f"  got: {calc_files_record}", file=sys.stderr)
                    return 2



        # policy binding per entry (optional unless policy-path supplied)
        if policy_sha256_expected is not None:
            if entry.get("policy_sha256") != policy_sha256_expected:
                print(f"FAIL: receipts[{i}] policy_sha256 mismatch vs policy-path", file=sys.stderr)
                return 2

        # Load pubkey + verify receipt cryptographically
        pj2 = _read_json(pp)
        pub_b64_2 = pj2.get("pubkey_b64")
        if not isinstance(pub_b64_2, str) or not pub_b64_2:
            print(f"FAIL: pubkey file invalid: {pp}", file=sys.stderr)
            return 2
        pub_raw_2 = _b64.urlsafe_b64decode(pub_b64_2 + "==")

        rj = _read_json(rp)
        sig2 = rj.get("signature")
        if not isinstance(sig2, dict):
            print(f"FAIL: receipt missing signature: {rp}", file=sys.stderr)
            return 2

        try:
            receipt = Receipt(
                run_id=rj["run_id"],
                policy_id=rj["policy_id"],
                call_id=rj["call_id"],
                command=rj["command"],
                cwd=rj["cwd"],
                started_at_ms=rj["started_at_ms"],
                finished_at_ms=rj["finished_at_ms"],
                exit_code=rj["exit_code"],
                stdout_b64=rj["stdout_b64"],
                stderr_b64=rj["stderr_b64"],
                stdout_sha256_b64=rj["stdout_sha256_b64"],
                stderr_sha256_b64=rj["stderr_sha256_b64"],
                policy_sha256=rj.get("policy_sha256"),
                policy_decision=rj.get("policy_decision"),
                deny_reason=rj.get("deny_reason"),
                signature=Signature(**sig2),
            )
        except Exception as e:
            print(f"FAIL: invalid receipt schema for {rp}: {e}", file=sys.stderr)
            return 2

        if not verify_receipt(pub_raw_2, receipt):
            print(f"FAIL: receipt verification failed for {rp}", file=sys.stderr)
            return 2

        # ---- Strict mode: enforce policy decisions recorded in receipts ----
        #
        # Default behavior is crypto  integrity only.
        # If --enforce-policy is set, fail on any denied receipt.
        #
        # NOTE: receipt JSON may be V1 (no policy_decision); treat missing as "allow".
        if enforce_policy:
            decision = rj.get("policy_decision", "allow")
            if decision == "deny":
                reason = rj.get("deny_reason") or "policy denied"
                print(f"FAIL: receipt denied by policy: {reason}", file=sys.stderr)
                return 2

        # Consistency checks vs manifest
        if run_id is not None and receipt.run_id != run_id:
            print(f"FAIL: receipt.run_id mismatch for {rp}", file=sys.stderr)
            return 2
        if policy_id is not None and receipt.policy_id != policy_id:
            print(f"FAIL: receipt.policy_id mismatch for {rp}", file=sys.stderr)
            return 2
        if receipt.call_id != entry["call_id"]:
            print(f"FAIL: receipt.call_id mismatch for {rp}", file=sys.stderr)
            return 2

    print("OK: manifest verified", file=sys.stderr)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    import base64 as _b64

    receipt_path = Path(args.receipt)
    pubkey_path = Path(args.pubkey)

    rj = _read_json(receipt_path)
    pj = _read_json(pubkey_path)

    pubkey_raw = _b64.urlsafe_b64decode(pj["pubkey_b64"] + "==")
    sig = rj["signature"]

    receipt = Receipt(
        run_id=rj["run_id"],
        policy_id=rj["policy_id"],
        call_id=rj["call_id"],
        command=rj["command"],
        cwd=rj["cwd"],
        started_at_ms=rj["started_at_ms"],
        finished_at_ms=rj["finished_at_ms"],
        exit_code=rj["exit_code"],
        stdout_b64=rj["stdout_b64"],
        stderr_b64=rj["stderr_b64"],
        stdout_sha256_b64=rj["stdout_sha256_b64"],
        stderr_sha256_b64=rj["stderr_sha256_b64"],
        # V2 fields are OPTIONAL but MUST be included when present,
        # otherwise verify_receipt() will fall back to V1 payload and
        # signature verification will fail for V2-signed receipts.
        policy_sha256=rj.get("policy_sha256"),
        policy_decision=rj.get("policy_decision"),
        deny_reason=rj.get("deny_reason"),
        signature=__import__("vaci.schema", fromlist=["Signature"]).Signature(**sig),
    )
    ok = verify_receipt(pubkey_raw, receipt)
    if not ok:
        print("FAIL: receipt verification failed", file=sys.stderr)
        return 2

    # Trust root enforcement (must be after signature verification)
    try:
        key_id = key_id_from_receipt_json(rj, pubkey_raw)
        assert_trusted_signer(key_id=key_id, trust_path=args.trust)
    except TrustError as e:
        print(f"FAIL: trust check failed: {e}", file=sys.stderr)
        return 2

    print("OK: receipt verified", file=sys.stderr)
    return 0

 
def cmd_presets(args: argparse.Namespace) -> int:
    """
    List built-in policy presets shipped with VACI.
    """
    for name in list_presets():
        print(name)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vaci")
    sp = ap.add_subparsers(dest="cmd", required=True)

    # Commit 2: keygen
    keyp = sp.add_parser("keygen", help="Generate a persistent gateway Ed25519 keyfile")
    keyp.add_argument(
        "--out",
        default=".vaci",
        help="Output dir or keyfile path. If a directory, writes gateway_ed25519.key  public_key_b64.json there (default: .vaci)",
    )

    keyp.set_defaults(fn=cmd_keygen)

    # Commit 2: trust add
    trustp = sp.add_parser("trust", help="Manage trusted signer keys")
    trustsp = trustp.add_subparsers(dest="trust_cmd", required=True)

    trust_add = trustsp.add_parser(
        "add",
        help="Add a signer key_id to trusted_keys.json using a public_key_b64.json file",
    )
    trust_add.add_argument("--pubkey", required=True, help="Path to public_key_b64.json")
    trust_add.add_argument("--trust", default=".vaci/trusted_keys.json", help="Trust store path (default: trusted_keys.json)")
    trust_add.set_defaults(fn=cmd_trust_add)

    runp = sp.add_parser("run", help="Run a command and emit signed receipt artifacts")
    runp.add_argument(
        "--out-dir",
        default=None,
        help="Directory to write receipt artifacts (default: env VACI_OUT_DIR or .vaci)",
    )
    runp.add_argument("--cwd", default=None, help="Working directory")
    runp.add_argument(
        "--keyfile",
        default=None,
        help="Gateway private keyfile (default: env VACI_KEYFILE or .vaci_keys/gateway_ed25519.key)",
    )

    runp.add_argument("--ephemeral", action="store_true", help="Use ephemeral key (dev/tests)")

    # NEW: ids
    runp.add_argument("--run-id", default=None, help="Run id (default: auto-generated)")
    runp.add_argument(
        "--policy-id",
        default=None,
        help="Policy id (default: env VACI_POLICY_ID or 'dev')",
    )
    runp.add_argument("--call-id", default=None, help="Call id (default: auto-generated per invocation)")
    runp.add_argument("--policy-path", default=None, help="Path to policy file; binds sha256 into receipts+manifest")

    # ---- Milestone 5: toolcall sidecar capture ----
    # Simple mode: provide tool name  args/result payloads (file or inline JSON)
    runp.add_argument("--tool", default=None, help="Optional tool name used by agent (e.g. 'web.search', 'db.query')")
    runp.add_argument("--tool-args", dest="tool_args", default=None, help="Path to JSON file containing tool args")
    runp.add_argument("--tool-args-json", dest="tool_args_json", default=None, help="Inline JSON string for tool args")
    runp.add_argument("--tool-result", dest="tool_result", default=None, help="Path to JSON file containing tool result")
    runp.add_argument("--tool-result-json", dest="tool_result_json", default=None, help="Inline JSON string for tool result")

    # Advanced mode: provide a prebuilt toolcall JSON file containing {tool,args,result}
    # If present, VACI will still write a stable toolcall_<call_id>.json into out_dir and bind it.
    runp.add_argument(
        "--toolcall-path",
        dest="toolcall_path",
        default=None,
        help="Path to prebuilt toolcall JSON containing {tool,args,result} (advanced)",
    )

        # ---- Milestone 6: files sidecar capture (file attestation) ----
    runp.add_argument(
        "--attest-git-changed",
        dest="attest_git_changed",
        action="store_true",
        help="Emit files_<call_id>.json for current git changed files (includes staged  unstaged).",
    )
    runp.add_argument(
        "--attest-path",
        dest="attest_paths",
        action="append",
        default=[],
        help="Emit files_<call_id>.json for all files under PATH (repeatable).",
    )

    runp.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute (use: vaci run -- <cmd>)")
    runp.set_defaults(fn=cmd_run)

    finp = sp.add_parser("finalize", help="Finalize run_manifest.json (lock session; prevents further appends)")
    finp.add_argument("--manifest", default=".vaci/run_manifest.json", help="Path to run_manifest.json")
    finp.add_argument(
    "--keyfile",
    default=".vaci/gateway_ed25519.key",
    help="Gateway private keyfile used to sign the manifest",
)
    finp.set_defaults(fn=cmd_finalize)

    verp = sp.add_parser("verify", help="Verify a receipt artifact")
    verp.add_argument("--receipt", default=".vaci/receipt.json")
    verp.add_argument("--pubkey", default=".vaci/public_key_b64.json")
    verp.add_argument(
        "--trust",
        default=".vaci/trusted_keys.json",
        help="Path to trusted signer key allowlist (default: trusted_keys.json)",
    )
    verp.set_defaults(fn=cmd_verify)

    mp = sp.add_parser("verify-manifest", help="Verify run_manifest.json (signature + hashes + receipts)")
    mp.add_argument("--manifest", default=".vaci/run_manifest.json")
    mp.add_argument(
        "--trust",
        default=".vaci/trusted_keys.json",
        help="Path to trusted signer key allowlist (default: trusted_keys.json)",
    )
    mp.add_argument("--pubkey", default=None, help="Optional override pubkey file (otherwise uses manifest receipts[0])")
    mp.add_argument("--require-finalized", action="store_true", help="Fail unless manifest finalized=true")
    mp.add_argument("--policy-path", default=None, help="Policy file path; recompute sha256 and compare to manifest")
    mp.add_argument(
        "--enforce-policy",
        action="store_true",
        help="Strict mode: fail verification if any receipt has policy_decision=deny (default: cryptohashes only)",
    )
    mp.set_defaults(fn=cmd_verify_manifest)

    pp = sp.add_parser("presets", help="List built-in policy presets shipped with VACI")
    
    pp.set_defaults(fn=cmd_presets)

    initp = sp.add_parser("init", help="Initialize a repo-local policy from a built-in preset")
    initp.add_argument(
        "--preset",
        required=True,
        help="Preset name (see: vaci presets)",
    )
    initp.add_argument(
        "--out",
        default="policy/policy.json",
        help="Where to write the policy file (default: policy/policy.json)",
    )
    initp.add_argument("--force", action="store_true", help="Overwrite policy file if it already exists")
    initp.add_argument("--gitignore", action="store_true", help='Add ".vaci/" to .gitignore (idempotent)')
    initp.add_argument("--gitignore-path", default=".gitignore", help="Path to .gitignore (default: .gitignore)")
    initp.set_defaults(fn=cmd_init)

    demop = sp.add_parser("demo", help="Run an end-to-end demo (allow  deny  finalize  verify)")
    demop.add_argument(
        "--preset",
        required=True,
        help="Preset name (see: vaci presets)",
    )
    demop.add_argument(
        "--out-dir",
        default=None,
        help="Optional output directory (default: .vaci/demo_runs/<run_id>/)",
    )
    demop.add_argument("--run-id", default=None, help="Optional explicit run id (default: derived from out dir name)")
    demop.add_argument(
        "--policy-path",
        default=None,
        help="Optional policy file path (default: writes preset policy into demo dir)",
    )
    demop.add_argument("--verbose", action="store_true", help="Print subcommands as they run")
    demop.set_defaults(fn=cmd_demo)

    sessp = sp.add_parser("session", help="Create a VACI session dir and print env exports")
    sessp.add_argument("--preset", required=True, help="Preset name (see: vaci presets)")
    sessp.add_argument("--run-id", default=None, help="Optional explicit run id (default: auto-generated)")
    sessp.add_argument("--base-dir", default=None, help="Base sessions dir (default: .vaci/sessions)")
    sessp.add_argument("--print-hint", action="store_true", help="Print usage hint to stderr")
    sessp.set_defaults(fn=cmd_session)

    bp = sp.add_parser("bundle", help="Create a portable .tgz bundle for a run_manifest  artifacts")
    bp.add_argument("--manifest", default=".vaci/run_manifest.json", help="Path to run_manifest.json")
    bp.add_argument("--out", required=True, help="Output bundle path (e.g., run_bundle.tgz)")
    bp.add_argument("--policy-path", default=None, help="Optional policy file to include as policy.json in the bundle")
    bp.set_defaults(fn=cmd_bundle)

    vbp = sp.add_parser("verify-bundle", help="Verify a portable bundle (.tgz)")
    vbp.add_argument("--bundle", required=True, help="Bundle path (.tgz)")
    vbp.add_argument(
        "--trust",
        default=".vaci/trusted_keys.json",
        help="Path to trusted signer key allowlist",
    )
    vbp.add_argument("--pubkey", default=None, help="Optional override pubkey file (otherwise uses receipts[0])")
    vbp.add_argument("--require-finalized", action="store_true", help="Fail unless manifest finalized=true")
    vbp.add_argument("--policy-path", default=None, help="Optional policy file path to bind/check against bundle manifest")
    vbp.add_argument(
        "--enforce-policy",
        action="store_true",
        help="Fail if any receipt has policy_decision=deny (default: cryptohashes only)",
    )
    vbp.set_defaults(fn=cmd_verify_bundle)

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