# src/vaci/core/policy.py
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


def load_policy(path: str | Path) -> Dict[str, Any]:
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    if not p.exists():
        raise FileNotFoundError(str(p))

    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("policy must be a JSON object")

    # version gate
    if data.get("version") != 1:
        raise ValueError("policy.version must be 1")

    # ---- schema (capabilities) ----
    # allow: list[str]          -> allowed executables (basename or exact argv0)
    # deny: list[str]           -> denied executables (basename or exact argv0)
    # cwd_allow: list[str]|null -> allowed cwd prefixes (absolute or relative-to-repo)
    # deny_shell: bool          -> if true, deny bash/sh/zsh/fish unless explicitly allowed
    # deny_arg_globs: list[str] -> if any arg path matches these globs, deny (protect paths)
    allow = data.get("allow", [])
    deny = data.get("deny", [])
    cwd_allow = data.get("cwd_allow", None)
    deny_shell = data.get("deny_shell", True)
    deny_arg_globs = data.get("deny_arg_globs", [])

    if allow is not None and (not isinstance(allow, list) or not all(isinstance(x, str) for x in allow)):
        raise ValueError("policy.allow must be a list[str]")
    if deny is not None and (not isinstance(deny, list) or not all(isinstance(x, str) for x in deny)):
        raise ValueError("policy.deny must be a list[str]")
    if cwd_allow is not None and (not isinstance(cwd_allow, list) or not all(isinstance(x, str) for x in cwd_allow)):
        raise ValueError("policy.cwd_allow must be null or list[str]")
    if not isinstance(deny_shell, bool):
        raise ValueError("policy.deny_shell must be a bool")
    if deny_arg_globs is not None and (not isinstance(deny_arg_globs, list) or not all(isinstance(x, str) for x in deny_arg_globs)):
        raise ValueError("policy.deny_arg_globs must be a list[str]")

    return data


def _is_probable_path(s: str) -> bool:
    # conservative heuristic: anything that looks like a path
    return (
        "/" in s
        or s.startswith("./")
        or s.startswith("../")
        or s.startswith("~")
        or s.startswith(".")
    )


def _normalize_path(arg: str, cwd: str) -> Optional[Path]:
    # Turn a command arg into an absolute normalized Path if it looks like a path.
    if not arg or not isinstance(arg, str):
        return None
    if not _is_probable_path(arg):
        return None

    p = Path(arg).expanduser()
    if not p.is_absolute():
        p = (Path(cwd) / p)
    try:
        return p.resolve()
    except Exception:
        # best-effort fallback; still deterministic enough
        return Path(str(p))


def evaluate(policy: Dict[str, Any], command: List[str], cwd: str) -> PolicyDecision:
    """
    Deterministic policy evaluator (V2-ish capabilities):

      1) deny list wins (basename or exact argv0)
      2) deny_shell blocks common shell trampolines unless explicitly allowed
      3) allow list gates execution (if non-empty)
      4) cwd_allow restricts execution to approved directories
      5) deny_arg_globs blocks protected path references (best-effort, conservative)

    Notes:
      - deny_arg_globs matches against both:
        a) absolute resolved path (string)
        b) repo-relative path (string) when possible
    """
    if not command:
        return PolicyDecision(False, "empty command")

    argv0 = command[0]
    exe = Path(argv0).name

    allow: List[str] = policy.get("allow", []) or []
    deny: List[str] = policy.get("deny", []) or []
    cwd_allow: Optional[List[str]] = policy.get("cwd_allow", None)
    deny_shell: bool = bool(policy.get("deny_shell", True))
    deny_arg_globs: List[str] = policy.get("deny_arg_globs", []) or []

    # 1) explicit deny
    if exe in deny or argv0 in deny:
        return PolicyDecision(False, f"executable denied: {exe}")

    # 2) deny shell trampolines (unless explicitly allowed)
    if deny_shell and exe in {"bash", "sh", "zsh", "fish"}:
        if not (exe in allow or argv0 in allow):
            return PolicyDecision(False, f"shell denied: {exe}")

    # 3) allow gate (if allow list is non-empty)
    if allow:
        if not (exe in allow or argv0 in allow):
            return PolicyDecision(False, f"executable not allowed: {exe}")

    # 4) cwd restriction
    if cwd_allow:
        try:
            cwd_resolved = Path(cwd).resolve()
        except Exception:
            cwd_resolved = Path(cwd)

        ok = False
        for allowed_prefix in cwd_allow:
            ap = Path(allowed_prefix).expanduser()
            if not ap.is_absolute():
                ap = (Path.cwd() / ap)
            try:
                ap = ap.resolve()
            except Exception:
                pass

            ap_str = str(ap)
            cwd_str = str(cwd_resolved)
            if cwd_str == ap_str or cwd_str.startswith(ap_str.rstrip("/") + "/"):
                ok = True
                break

        if not ok:
            return PolicyDecision(False, f"cwd not allowed: {cwd_resolved}")

    # 5) deny protected paths in args (conservative)
    if deny_arg_globs:
        # repo root = current process cwd (policy decision should be deterministic in CI)
        try:
            repo_root = Path.cwd().resolve()
        except Exception:
            repo_root = Path.cwd()

        for a in command[1:]:
            p = _normalize_path(a, cwd)
            if p is None:
                continue

            abs_s = str(p)
            rel_s = None
            try:
                rel_s = str(p.relative_to(repo_root))
            except Exception:
                rel_s = None

            for pat in deny_arg_globs:
                # match against absolute or repo-relative forms
                if Path(abs_s).match(pat):
                    return PolicyDecision(False, f"arg path denied by glob '{pat}': {abs_s}")
                if rel_s and Path(rel_s).match(pat):
                    return PolicyDecision(False, f"arg path denied by glob '{pat}': {rel_s}")

    return PolicyDecision(True, "allowed")