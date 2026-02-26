# VACI Cryptographic Spec (v1)

This document defines the minimal, stable cryptographic contract for VACI artifacts.

Goals:
- Deterministic hashing/signing across platforms and languages
- Clear “what is signed” and “what is hashed”
- Golden test vectors to prevent accidental drift

## 1. Canonical JSON

Canonical JSON bytes are produced by:

- UTF-8 encoding
- Keys sorted (`sort_keys=True`)
- No whitespace (`separators=(",", ":")`)
- `ensure_ascii=False`

In Python, this is:

```py
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")