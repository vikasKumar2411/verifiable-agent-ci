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
- ✅ Verifiable CI artifacts

This is a minimal execution trust layer for AI agents.

---

## Why VACI Exists

LLM agents can:
- call tools
- run shell commands
- modify repos
- fetch network resources

But today, there is no cryptographic proof of:

- what actually ran
- under which policy
- signed by which identity
- in what order
- whether something was denied

VACI provides that missing execution layer.

It is:

- Lightweight
- Deterministic
- CI-friendly
- Agent-friendly

---

# 🚀 Quickstart (2 Minutes)

Install:

```bash
pip install -e .