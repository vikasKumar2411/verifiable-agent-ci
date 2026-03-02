# Threat Model — VACI (Verifiable Agent Command Infrastructure)

## Summary

VACI turns tool/command execution into **cryptographically verifiable artifacts**.

Given a VACI run directory (or bundle), a verifier can confirm:

- **What** commands/tools were executed (or denied)
- **In what order**
- **Under which policy**
- **By which signing identity**
- With **tamper-evident binding** to stdout/stderr, toolcall args/results, and referenced artifacts

VACI is an **execution attestation layer**. It proves *what happened*, not *whether it was a good idea*.

---

## Security Goals

### G1 — Tamper-evident receipts
If any receipt content changes (command, cwd, stdout/stderr, exit code, policy decision, deny reason), verification fails.

### G2 — Tamper-evident session ledger
The run manifest forms an append-only chain:
- You cannot reorder entries
- You cannot delete entries
- You cannot splice entries from another run
…without detection.

### G3 — Identity binding (trust-root enforcement)
A run is only valid if:
- The manifest signature verifies, and
- The signer key_id is present in the verifier’s trust store (trusted_keys.json)

### G4 — Policy binding
Receipts + manifest bind to `policy_sha256` so a verifier can confirm the run was executed under the expected policy file.

### G5 — Deterministic denial transparency
When policy denies a command/tool, VACI emits a **signed denial receipt** including a stable deny reason.
A deny cannot be hidden without breaking the chain.

### G6 — Toolcall attestation (optional)
If toolcall sidecars are used, VACI binds:
- tool name
- tool args
- tool result
- toolcall file hashes
into the manifest entry, so edits are detected.

---

## Attacker Model

VACI is designed to defend against **post-execution tampering** and **artifact forgery**.

We assume an attacker may be able to:

- Modify files in the run directory after execution (edit receipts, toolcalls, manifests)
- Replace artifacts with versions from another run
- Delete receipts to hide actions
- Reorder receipts to change the narrative
- Change the policy file after the run and claim it was used
- Attempt to present a run signed by an untrusted identity

---

## What VACI Defends Against

### A1 — Editing execution outputs after the fact
Changing stdout/stderr, exit codes, command args, cwd, timestamps, or policy decision breaks receipt signature verification and/or file hash checks.

### A2 — Reordering or deleting execution steps
Each manifest entry includes a `prev_entry_hash` chain; reorder/delete breaks the chain integrity checks.

### A3 — Swapping in receipts from another run
Entries are chained and include run-level invariants (run_id/policy_id/policy_sha256 consistency checks).
Mixing entries from different runs is detected.

### A4 — “Pretend this policy was used”
If verification is performed with `--policy-path`, VACI recomputes `policy_sha256` and rejects mismatches.

### A5 — Hiding denied actions
Denied actions generate signed receipts and occupy a position in the manifest chain.
Removing them breaks the chain.

### A6 — Toolcall tampering (when enabled)
Toolcall sidecar hashes and record binding hashes are checked.
Editing args/results/tool name breaks verification.

### A7 — Untrusted signer
Even if a signature is valid, verification fails if signer key_id is not in the trust store.

---

## What VACI Does NOT Defend Against (Non-goals)

### N1 — A malicious host lying during execution
If the OS/kernel/runtime is compromised, an attacker may:
- fake command results
- capture secrets
- modify running processes
VACI will faithfully attest to whatever the compromised environment produced.

Mitigation (out of scope for VACI itself): TEEs, hardened runners, hermetic builds, remote attestation, locked-down CI.

### N2 — Preventing data exfiltration at runtime
VACI can **record** that a tool/command was used and can **deny** certain executables/args,
but it does not prevent a compromised system from leaking data.

### N3 — Ensuring the agent’s intent was correct
VACI does not judge whether an action was “safe” or “aligned” — it only proves what happened under a given policy.

### N4 — Protecting private keys if the machine is compromised
If the signing key is stolen, an attacker can produce runs that appear authentic.
Trust stores must be managed like production credentials.

Mitigations: key rotation, hardware-backed keys, short-lived keys, CI secrets hygiene.

### N5 — Time integrity / trusted timestamps
`started_at_ms` / `finished_at_ms` are attested values from the runtime environment.
They are not independently time-stamped by a trusted authority.

Mitigations: external timestamping services (optional future integration).

---

## Trust Assumptions

VACI’s guarantees hold under these assumptions:

1. **The signer private key remains secret**
2. **The verifier’s trust store is correct** (trusted_keys.json includes only allowed signers)
3. **The verifier runs verification on the artifacts they were given**
4. **The policy file provided to the verifier is the intended policy** (if policy binding is enforced)

---

## What “Verified” Means

When `vaci verify-manifest` succeeds, it proves:

- The manifest payload hash matches the declared manifest_hash
- The manifest signature is valid for that payload
- The signer is trusted (key_id is in trust store)
- Each entry’s receipt and pubkey files match recorded sha256
- Each receipt’s signature is valid
- The receipt chain (`prev_entry_hash`) is intact
- If `--policy-path` is provided: manifest + entries bind to that policy’s sha256
- If `--enforce-policy` is provided: no denied receipts exist in the run
- If toolcall sidecars are present: their hashes and bindings verify

---

## Recommended Verification Modes

### Integrity-only (default)
Use when you need authenticity + tamper evidence.

- `vaci verify-manifest --manifest ... --trust ...`

### Require finalization
Use for CI artifact publication.

- `--require-finalized`

### Enforce policy decisions
Use when any denial should fail the run.

- `--enforce-policy`

### Enforce policy binding
Use when a specific policy must be proven.

- `--policy-path policy/policy.json`

---

## Future Hardening Ideas (Optional)

These are compatible extensions, not requirements:

- Signed policy files / policy provenance
- External timestamping / transparency logs
- DSSE envelopes / Sigstore integration
- Hermetic runners (containerized execution)
- Remote attestation (TEE-backed execution proofs)

---