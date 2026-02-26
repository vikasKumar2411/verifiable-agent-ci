## Usage

VACI lets you run commands and produce **cryptographically verifiable receipts** plus a **session manifest** (`run_manifest.json`) that chains multiple calls together. You can optionally bind runs to a specific policy file hash.

### 1) Generate a persistent gateway key

```bash
python -m vaci.cli keygen --out .vaci_keys/gateway_ed25519.key