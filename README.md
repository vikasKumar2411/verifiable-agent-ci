VACI — Verifiable Agent Continuous Integration

VACI (Verifiable Agent Continuous Integration) is a cryptographic execution harness for AI agents and CI systems.

It turns command and tool execution into tamper-evident, cryptographically verifiable artifacts.

VACI provides:

🔐 Ed25519 signed execution receipts

📜 Hash-linked run manifests

🧱 Policy-bound execution guarantees

🛡️ Deterministic denial receipts

📦 Portable verification bundles

🔍 Toolcall attestation (args + results integrity)

🧾 File attestation (repo/artifact tamper detection)

Minimal. Deterministic. Verifiable.

🚀 Quickstart (2 Minutes)
Install
git clone https://github.com/vikasKumar2411/verifiable-agent-ci.git
cd verifiable-agent-ci

python -m venv .venv
source .venv/bin/activate

pip install -e .
pytest -q
Start a Verifiable Session
python -m vaci.cli session --preset pr-agent

Copy and execute the exported environment variables shown in output.

Run Commands
python -m vaci.cli run -- pytest -q
python -m vaci.cli run -- echo "hello"

Each run produces:

A signed receipt

A chained manifest entry

Optional sidecars (if enabled)

Finalize + Verify
python -m vaci.cli finalize --manifest $VACI_OUT_DIR/run_manifest.json

python -m vaci.cli verify-manifest \
  --manifest $VACI_OUT_DIR/run_manifest.json \
  --trust $VACI_TRUST \
  --policy-path $VACI_POLICY_PATH \
  --enforce-policy

If anything was:

Reordered

Deleted

Re-signed

Policy-violating

Tampered

Verification fails.

Why VACI Exists

AI agents can:

Execute shell commands

Modify repositories

Call external tools

Fetch network resources

Perform multi-step workflows

But today there is typically no cryptographic proof of:

What actually ran

In what order

Under which policy

Signed by which identity

Whether something was denied

Whether tool inputs/outputs were modified

Whether referenced files were altered

VACI provides that missing execution trust layer.

Core Guarantees
🔐 Signed Receipts

Every command execution produces a signed receipt containing:

run_id

policy_id

call_id

command + cwd

timestamps

exit code

stdout/stderr digests

optional policy binding

optional file/tool attestations

Receipts are signed with Ed25519.

📜 Hash-Linked Manifest

Receipts are chained:

prev_entry_hash → entry_hash

Reordering or deletion breaks verification

Manifest is signed and hash-bound

🧱 Policy Binding

When a policy is supplied:

policy_sha256 is bound into receipts

Allow/deny decisions are signed

Denials produce deterministic signed receipts

--enforce-policy fails verification if violations exist

🧾 File Attestation

Optional sidecars record SHA256 digests of:

Git changed files (--attest-git-changed)

Artifact directories (--attest-path <dir>)

Prevents silent modification of:

Repository contents

Build artifacts

Generated outputs

Verification Invariants

verify-manifest enforces:

Manifest signature integrity

Receipt signature validity

Receipt chain integrity

No duplicate call_id

Monotonic timestamps

Single signer across manifest

Sidecar hash integrity

Policy consistency (if supplied)

Portable Bundles

Create a verification bundle:

python -m vaci.cli bundle \
  --manifest $VACI_OUT_DIR/run_manifest.json \
  --trust $VACI_TRUST \
  --out demo_bundle.tgz

Verify elsewhere:

python -m vaci.cli verify-bundle demo_bundle.tgz
Intended Use Cases

Agentic CI enforcement

PR automation auditing

Secure LLM tool execution

Reproducible automation workflows

Cryptographic execution attestations

Defense against silent tool misuse

Security Model

VACI assumes:

The signing key is protected

Verification occurs against a trusted key store

Policies are deterministic and hashed

VACI protects against:

Receipt deletion

Receipt reordering

Mixed-signer injection

Policy swapping

Toolcall tampering

File/artifact tampering

Silent command denial

Manifest mutation

Status

Fully functional CLI

Session support

Multi-receipt manifests

Policy enforcement

Sidecar attestations

Portable bundles

Passing test suite

License

MIT


---

This version is:

- Clean
- Runnable
- Security-serious
- Not bloated
- Appropriate for GitHub discovery
- Appropriate for security engineers reviewing infra

---

If you want next:

We can add a **small architecture diagram section** (ASCII style) that makes this feel even mor