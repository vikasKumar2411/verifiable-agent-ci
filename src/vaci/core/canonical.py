# src/vaci/core/canonical.py
from __future__ import annotations

import json
from typing import Any


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Canonical-ish JSON bytes for signing/hashing.

    Rules (intentionally strict + stable):
    - UTF-8 encoding
    - Objects: keys sorted lexicographically
    - No insignificant whitespace (separators=(",", ":"))
    - ensure_ascii=False (UTF-8, not \\u escapes)
    - Disallow NaN/Infinity (not portable across JSON parsers)

    NOTE:
    This is not a full RFC 8785 JCS implementation (yet),
    but it's deterministic and cross-runtime friendly for the data shapes we use.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")