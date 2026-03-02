# VACI — Verifiable Agent Command Infrastructure

VACI turns command execution into **cryptographically verifiable artifacts**.

If your AI agent runs:

- `pytest`
- `pip install`
- `terraform apply`
- `curl`
- or any local tool

VACI produces:

- 🔐 Signed receipts (Ed25519)
- 📜 A chained session manifest
- 🧱 Policy-bound execution guarantees
- 🛡️ Deterministic denial receipts
- 📦 Portable verification bundles
- 🔍 Toolcall attestation (args + results tamper detection)
- 🧾 File attestation (changed files / artifact directories tamper detection)

This is a minimal execution trust layer for AI agents and CI systems.

---

# Why VACI Exists

LLM agents can:

- Call tools
- Execute shell commands
- Modify repositories
- Fetch network resources
- Perform multi-step workflows

But today, there is no cryptographic proof of:

- What actually ran
- Under which policy
- In what order
- Signed by which identity
- Whether something was denied
- Whether tool inputs/outputs were modified
- Whether repo/artifact files referenced by the agent were modified

VACI provides that missing execution layer.

It is:

- Deterministic
- CI-friendly
- Agent-friendly
- Cryptographically verifiable
- Lightweight

# Manifest Verification Invariants

When you run:

```bash
python -m vaci.cli verify-manifest --manifest .vaci/run_manifest.json --trust .vaci/trusted_keys.json
```

VACI verifies:

- The manifest signature  manifest hash (tamper detection)
- The receipt chain (`prev_entry_hash` → `entry_hash`) to detect reorder/delete
- All referenced files match their recorded sha256 (receipts, pubkeys, sidecars)

Additionally, VACI enforces these **strict invariants**:

- **No duplicate `call_id`** in `receipts[]`
- **Monotonic `created_at_ms`** across `receipts[]` (non-decreasing)
- **Single signer** across all entries (prevents mixed-signer manifests)
---

# 🧾 File Attestation (changed files / artifacts)

You can optionally bind a **files sidecar** to each receipt entry:

- `--attest-git-changed` records digests for currently changed files (staged  unstaged)
- `--attest-path <PATH>` records digests for all files under a directory (repeatable)

Example:

```bash
python -m vaci.cli run --policy-id demo --attest-git-changed -- pytest -q
python -m vaci.cli run --policy-id demo --attest-path dist/ -- echo "built artifacts"
python -m vaci.cli verify-manifest --manifest .vaci/run_manifest.json --trust .vaci/trusted_keys.json
```

This emits `files_<call_id>.json` and binds its sha256  record hash into the manifest entry.


# 🚀 Quickstart (2 Minutes)

## Install

```bash
pip install -e .