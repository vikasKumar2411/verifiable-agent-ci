#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Demo: VACI verifiable execution + manifest + trust + (optional) policy enforcement
#
# Usage:
#   ./scripts/demo_vaci.sh              # defaults to MODE=audit
#   MODE=enforce ./scripts/demo_vaci.sh # fails build if any receipt was denied
#
# Outputs:
#   demo_out/  (run_manifest.json + receipts + pubkeys + trusted_keys.json)
# -----------------------------------------------------------------------------

MODE="${MODE:-audit}"  # audit | enforce

rm -rf .vaci .vaci_keys demo_out demo
mkdir -p demo_out demo

# 1) key
python -m vaci.cli keygen --out .vaci_keys/gateway_ed25519.key

# 2) policy (matches current src/vaci/core/policy.py)
#    - allow: explicit allowlist
#    - deny: explicit denylist
#    - cwd_allow: single prefix string (not a list)
cat > demo/policy.json <<'JSON'
{
  "version": 1,
  "allow": ["echo", "python", "pytest"],
  "deny":  ["curl", "wget", "nc", "ssh"],
  "cwd_allow": "."
}
JSON

# 3) run-id
RID="demo_$(python - <<'PY'
import uuid
print(uuid.uuid4().hex)
PY
)"

echo
echo "==> MODE=${MODE}"
echo "==> RUN_ID=${RID}"
echo

# 4) allowed run
python -m vaci.cli run \
  --out-dir demo_out \
  --keyfile .vaci_keys/gateway_ed25519.key \
  --run-id "$RID" \
  --policy-id demo \
  --policy-path demo/policy.json \
  -- echo "OK: allowed command"

# 5) denied run (should still produce a signed denial receipt)
python -m vaci.cli run \
  --out-dir demo_out \
  --keyfile .vaci_keys/gateway_ed25519.key \
  --run-id "$RID" \
  --policy-id demo \
  --policy-path demo/policy.json \
  -- curl https://example.com || true

# 6) trust store pinned to signer
python -m vaci.cli trust add \
  --pubkey demo_out/public_key_b64.json \
  --trust  demo_out/trusted_keys.json

# 7) finalize
python -m vaci.cli finalize \
  --manifest demo_out/run_manifest.json \
  --keyfile  .vaci_keys/gateway_ed25519.key

echo
echo "=== Verify manifest WITHOUT policy-path (crypto + hashes + chain) ==="
python -m vaci.cli verify-manifest \
  --manifest demo_out/run_manifest.json \
  --trust    demo_out/trusted_keys.json \
  --require-finalized

echo
echo "=== Report denied receipts (from manifest) ==="
python - <<'PY'
import json
from pathlib import Path

m = Path("demo_out/run_manifest.json")
mj = json.loads(m.read_text(encoding="utf-8"))
base = m.parent

denied = []
for e in mj.get("receipts", []):
    rp = base / e["receipt_path"]
    rj = json.loads(rp.read_text(encoding="utf-8"))
    if rj.get("policy_decision") == "deny":
        denied.append({
            "call_id": rj.get("call_id"),
            "cmd": " ".join(rj.get("command") or []),
            "reason": rj.get("deny_reason") or "(no deny_reason)",
            "receipt": str(rp),
        })

if not denied:
    print("No denied receipts.")
else:
    print(f"Denied receipts: {len(denied)}")
    for i, d in enumerate(denied, 1):
        print(f"  {i}) call_id={d['call_id']}")
        print(f"     cmd:    {d['cmd']}")
        print(f"     reason: {d['reason']}")
        print(f"     file:   {d['receipt']}")
PY

if [[ "${MODE}" == "enforce" ]]; then
  echo
  echo "=== Verify manifest WITH policy-path (ENFORCEMENT: denied => FAIL) ==="
  # This will exit non-zero if any receipt was denied by policy.
  python -m vaci.cli verify-manifest \
    --manifest demo_out/run_manifest.json \
    --trust    demo_out/trusted_keys.json \
    --require-finalized \
    --policy-path demo/policy.json
else
  echo
  echo "=== Verify manifest WITH policy-path (AUDIT: expected to fail if denied exists) ==="
  python -m vaci.cli verify-manifest \
    --manifest demo_out/run_manifest.json \
    --trust    demo_out/trusted_keys.json \
    --require-finalized \
    --policy-path demo/policy.json || true
fi

echo
echo "Demo complete. Artifacts in demo_out/"