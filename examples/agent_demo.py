# examples/agent_demo.py
from vaci.runner import SafeAgentRunner

def _print(receipt, art):
    dec = getattr(receipt, "policy_decision", None) or "allow"
    reason = getattr(receipt, "deny_reason", None)
    print(f"- decision={dec} exit={receipt.exit_code} receipt={art.receipt_path}")
    if reason:
        print(f"  deny_reason: {reason}")

def main():
    r = SafeAgentRunner(
        out_dir="demo_out_runner",
        ephemeral=True,          # easy local demo
        policy_id="demo",
        policy_path="demo/policy.json",
        run_id="demo_runner_1",
    )

    # allowed
    receipt1, art1 = r.run(["echo", "hello from runner"])
    _print(receipt1, art1)

    # denied (if policy denies curl)
    receipt2, art2 = r.run(["curl", "https://example.com"])
    _print(receipt2, art2)

    manifest = r.finalize()
    print("finalized:", manifest)

if __name__ == "__main__":
    main()