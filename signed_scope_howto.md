### `signed_scope_howto.md`
```markdown
## Using Signed Scope in Attack Surface Mapper

Signed scope is the authorization guardrail. The scanner only runs against targets listed in `scope.json` that has a valid HMAC signature.

### Step 1: Create `scope.json`

Use the bundled helper:

```bash
python3 create_scope.py
Or create it manually:

import json, hashlib, hmac

targets = [
    "example.com",
    "api.example.com",
    "192.168.1.0/24",
]
secret = "replace-with-strong-secret"

payload = json.dumps({"allowed_targets": targets}, sort_keys=True).encode("utf-8")
signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

with open("scope.json", "w", encoding="utf-8") as f:
    json.dump({"allowed_targets": targets, "signature": signature}, f, indent=2)
Step 2: Run the scanner
export RECON_SCOPE_SECRET="your-secret"
python3 attack-surface-mapper.py example.com \
  --scope-file scope.json \
  --depth standard \
  --output-dir results/example.com
Step 3: Optional scope update from file
python3 attack-surface-mapper.py --file targets.txt \
  --scope-file scope.json \
  --update-scope \
  --depth passive
--update-scope will:

read targets from --file

canonicalize/validate each target

merge valid entries into scope.json

re-sign the scope with the same secret

Invalid targets are skipped and logged.


---