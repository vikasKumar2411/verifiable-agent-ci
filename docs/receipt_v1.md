# VACI Receipt v1 (Signed Execution Receipt)

This document defines the **Receipt v1 contract** used by VACI to prove that a command/tool execution actually happened.

Receipt v1 is designed to:
- be **cheap to generate**
- be **cheap to verify**
- prevent “agent fabricated tool outputs” by requiring a valid signature over a canonical payload
- stay stable as adapters/framework integrations evolve

---

## 1) Receipt Artifact Files (CLI)

`vaci run --out-dir <DIR> -- <cmd>` emits:

- `<DIR>/receipt.json`  — signed receipt
- `<DIR>/public_key_b64.json` — Ed25519 public key used to verify the receipt

---

## 2) Receipt JSON Shape (v1)

Receipt v1 is the JSON output of `vaci.gateway.Receipt.to_dict()`.

Required keys:

- `command`: list[string]  
- `cwd`: string
- `started_at_ms`: int
- `finished_at_ms`: int
- `exit_code`: int
- `stdout_b64`: string (urlsafe base64, no padding)
- `stderr_b64`: string (urlsafe base64, no padding)
- `stdout_sha256_b64`: string (urlsafe base64 of sha256(stdout))
- `stderr_sha256_b64`: string (urlsafe base64 of sha256(stderr))
- `signature`: object
  - `alg`: "ed25519"
  - `key_id`: string (identifier derived from public key)
  - `sig_b64`: string (urlsafe base64, no padding)

NOTE: Although the receipt contains stdout/stderr bytes (as base64), the signature does **not** sign raw stdout/stderr; it signs their hashes.

---

## 3) What Is Signed (Canonical Payload)

The receipt signature is computed over this canonical payload object:

```json
{
  "command": [...],
  "cwd": "...",
  "started_at_ms": 0,
  "finished_at_ms": 0,
  "exit_code": 0,
  "stdout_sha256_b64": "...",
  "stderr_sha256_b64": "..."
}