# src/vaci/adapters/tool_ledger.py
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


def _sha256_obj(obj: Any) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


@dataclass(frozen=True)
class ToolCallRecord:
    """
    Minimal “agent runtime ledger” record:
    - tool: tool name/id
    - args: JSON-serializable args dict
    - result: JSON-serializable result dict
    - hashes: canonical sha256 over args+result
    """
    tool: str
    args: Any
    result: Any
    args_sha256: str
    result_sha256: str
    toolcall_sha256: str

    @classmethod
    def make(cls, *, tool: str, args: Any, result: Any) -> "ToolCallRecord":
        args_h = _sha256_obj(args)
        result_h = _sha256_obj(result)
        toolcall_h = _sha256_obj({"tool": tool, "args": args, "result": result})
        return cls(
            tool=tool,
            args=args,
            result=result,
            args_sha256=args_h,
            result_sha256=result_h,
            toolcall_sha256=toolcall_h,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "args": self.args,
            "result": self.result,
            "args_sha256": self.args_sha256,
            "result_sha256": self.result_sha256,
            "toolcall_sha256": self.toolcall_sha256,
        }


def write_toolcall_json(out_path: Path, record: ToolCallRecord) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()