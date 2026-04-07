## One-liner signed scope creation

Run this command and edit the `targets` list inline before executing:

```
python3 -c '
import json, hashlib, hmac, sys
print("=== Signed Scope Creator ===\n")
targets = ["example.com", "api.example.com", "192.168.1.0/24"]
secret = input("Enter secret key: ").strip()
if len(secret) < 8:
    print("Secret must be at least 8 characters.")
    sys.exit(1)
payload = json.dumps({"allowed_targets": targets}, sort_keys=True).encode("utf-8")
signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
with open("scope.json", "w", encoding="utf-8") as f:
    json.dump({"allowed_targets": targets, "signature": signature}, f, indent=2)
print("scope.json created")
'
```
## Keep the secret safe; you need it as RECON_SCOPE_SECRET (or --scope-secret) when running the scanner.
