## How to Use Signed Scope in the Recon Agent
### Why Signed Scope Exists
### The signed scope is a security guardrail. It forces you to explicitly list every target you are allowed to scan and cryptographically sign that list.

## One-Liner Scope Creation (Recommended)
### Copy and paste this single command. It will prompt you for a secret and create scope.json instantly:

```
python3 -c '
import json, hashlib, hmac, sys
print("=== Recon Agent - One-Liner Signed Scope Creator ===\n")
targets = [
    "example.com",
    "api.example.com",
    "test.example.com",
    "192.168.1.0/24"
]
secret = input("Enter a strong secret key (keep this safe!): ").strip()
if len(secret) < 8:
    print("❌ Secret must be at least 8 characters.")
    sys.exit(1)
payload = json.dumps({"allowed_targets": targets}, sort_keys=True).encode("utf-8")
signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
scope_data = {"allowed_targets": targets, "signature": signature}
with open("scope.json", "w", encoding="utf-8") as f:
    json.dump(scope_data, f, indent=2)
print("\n✅ scope.json created successfully!")
print(f"   Targets authorized: {len(targets)}")
print("   Keep your secret key safe!")
'
```

## How to customize:

###Edit the targets = [...] list directly in the command before running.

### Run it in any folder where you want scope.json to be created.