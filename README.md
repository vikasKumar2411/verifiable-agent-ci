# VACI — Verifiable Agent Continuous Integration

**VACI** is a cryptographic execution harness for AI agents and CI systems.

It turns command and tool execution into tamper-evident, cryptographically verifiable artifacts.

### VACI provides:

- 🔐 Ed25519 signed execution receipts
- 📜 Hash-linked run manifests
- 🧱 Policy-bound execution guarantees
- 🛡️ Deterministic denial receipts
- 📦 Portable verification bundles
- 🔍 Toolcall attestation (args + results integrity)
- 🧾 File attestation (repo/artifact tamper detection)

> **Minimal. Deterministic. Verifiable.**

---

## 🚀 Quickstart (2 Minutes)

### Install
```bash
git clone https://github.com/vikasKumar2411/verifiable-agent-ci.git
cd verifiable-agent-ci

python -m venv .venv
source .venv/bin/activate

pip install -e .
pytest -q
```

### Start a Verifiable Session
```bash
python -m vaci.cli session --preset pr-agent
```

Copy and execute the exported environment variables shown in output.

### Run Commands
```bash
python -m vaci.cli run -- pytest -q
python -m vaci.cli run -- echo "hello"
```

Each run produces:
- A signed receipt
- A chained manifest entry
- Optional sidecars (if enabled)

### Finalize + Verify
```bash
python -m vaci.cli finalize --manifest $VACI_OUT_DIR/run_manifest.json

python -m vaci.cli verify-manifest \
  --manifest $VACI_OUT_DIR/run_manifest.json \
  --trust $VACI_TRUST \
  --policy-path $VACI_POLICY_PATH \
  --enforce-policy
```

If anything was reordered, deleted, re-signed, policy-violating, or tampered — **verification fails**.

---

## Why VACI Exists

AI agents can:
- Execute shell commands
- Modify repositories
- Call external tools
- Fetch network resources
- Perform multi-step workflows

But today there is typically **no cryptographic proof** of:
- What actually ran
- In what order
- Under which policy
- Signed by which identity
- Whether something was denied
- Whether tool inputs/outputs were modified
- Whether referenced files were altered

**VACI provides that missing execution trust layer.**

---

## Architecture
```
┌─────────────────────────────────────────────┐
│                    Agent                    │
│        (LLM / CI runner / automation)       │
└───────────────────┬─────────────────────────┘
                    │  command / tool call
                    ▼
┌─────────────────────────────────────────────┐
│             VACI Gateway                    │
│   • applies policy (allow / deny)           │
│   • signs execution with Ed25519 key        │
│   • captures stdout/stderr digests          │
└───────────────────┬─────────────────────────┘
                    │  signed artifact
                    ▼
┌─────────────────────────────────────────────┐
│               Receipt                       │
│   run_id · call_id · command · timestamps   │
│   exit code · output digests · policy_sha   │
└───────────────────┬─────────────────────────┘
                    │  chained via prev_entry_hash
                    ▼
┌─────────────────────────────────────────────┐
│           Manifest (hash chain)             │
│   receipt₁ → receipt₂ → receipt₃ → …       │
│   reorder or delete = broken chain          │
└───────────────────┬─────────────────────────┘
                    │  verify-manifest / verify-bundle
                    ▼
┌─────────────────────────────────────────────┐
│           Verifier (trust root)             │
│   • validates signatures                    │
│   • enforces chain integrity                │
│   • checks policy compliance               │
│   • confirms sidecar hashes                 │
└─────────────────────────────────────────────┘
```

---

## Core Guarantees

### 🔐 Signed Receipts

Every command execution produces a signed receipt containing:

| Field | Description |
|---|---|
| `run_id` | Unique session identifier |
| `policy_id` | Bound policy reference |
| `call_id` | Per-command identifier |
| `command + cwd` | What ran and where |
| `timestamps` | Start/end times |
| `exit code` | Result code |
| `stdout/stderr digests` | Output integrity hashes |

Receipts are signed with **Ed25519**.

### 📜 Hash-Linked Manifest

Receipts are chained:
```
prev_entry_hash → entry_hash
```

Reordering or deletion breaks verification. The manifest itself is signed and hash-bound.

### 🧱 Policy Binding

When a policy is supplied:
- `policy_sha256` is bound into receipts
- Allow/deny decisions are signed
- Denials produce deterministic signed receipts
- `--enforce-policy` fails verification if violations exist

### 🧾 File Attestation

Optional sidecars record SHA256 digests of:
- Git changed files (`--attest-git-changed`)
- Artifact directories (`--attest-path <dir>`)

Prevents silent modification of repository contents, build artifacts, and generated outputs.

---

## Verification Invariants

`verify-manifest` enforces:

- Manifest signature integrity
- Receipt signature validity
- Receipt chain integrity
- No duplicate `call_id`
- Monotonic timestamps
- Single signer across manifest
- Sidecar hash integrity
- Policy consistency (if supplied)

---

## Portable Bundles

Create a verification bundle:
```bash
python -m vaci.cli bundle \
  --manifest $VACI_OUT_DIR/run_manifest.json \
  --trust $VACI_TRUST \
  --out demo_bundle.tgz
```

Verify elsewhere:
```bash
python -m vaci.cli verify-bundle demo_bundle.tgz
```

---

## Intended Use Cases

- Agentic CI enforcement
- PR automation auditing
- Secure LLM tool execution
- Reproducible automation workflows
- Cryptographic execution attestations
- Defense against silent tool misuse

---

## Security Model

**VACI assumes:**
- The signing key is protected
- Verification occurs against a trusted key store
- Policies are deterministic and hashed

**VACI protects against:**
- Receipt deletion
- Receipt reordering
- Mixed-signer injection
- Policy swapping
- Toolcall tampering
- File/artifact tampering
- Silent command denial
- Manifest mutation

---

## Status

- ✅ Fully functional CLI
- ✅ Session support
- ✅ Multi-receipt manifests
- ✅ Policy enforcement
- ✅ Sidecar attestations
- ✅ Portable bundles
- ✅ Passing test suite

---

## License

[MIT](LICENSE)