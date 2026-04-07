## How to Use Signed Scope in the Recon Agent

### Why Signed Scope Exists
The signed scope is a security guardrail. It forces you to explicitly list every target you are allowed to scan and cryptographically sign that list. This prevents accidental or unauthorized scans.

### Step 1: Create Your Signed scope.json

1.  Save the script below as create_scope.py:
```
#!/usr/bin/env python3
import json
import hashlib
import hmac
import sys

print("=== Recon Agent - Create Signed Scope ===\n")

=== EDIT THIS LIST ===
targets = [
    "example.com",
    "api.example.com",
    "test.example.com",
    "192.168.1.0/24",      # CIDR ranges are supported
    # Add as many domains, IPs, or CIDRs as needed
]

secret = input("Enter a strong secret key (keep this safe!): ").strip()
if len(secret) < 8:
    print("Secret must be at least 8 characters.")
    sys.exit(1)

Create payload and HMAC signature
payload = json.dumps({"allowed_targets": targets}, sort_keys=True).encode("utf-8")
signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

scope_data = {
    "allowed_targets": targets,
    "signature": signature
}

with open("scope.json", "w", encoding="utf-8") as f:
    json.dump(scope_data, f, indent=2)

print("\nscope.json created successfully!")
print(f"   Targets authorized: {len(targets)}")
print(f"   Signature: {signature[:16]}... (full signature saved in file)")
print("\nKeep your secret key safe — you'll need it to run the agent.")
```

2.  Run It:
```
python3 create_scope.py
```

## Step 2: Run the Recon Agent with the Signed Scope
Basic command:
```
python3 recon_agent.py example.com \
  --scope-file scope.json \
  --scope-secret "your-secret-key-here" \
  --depth deep \
  --output-dir results/example.com
  ```


## Recommended (more secure — secret never in shell history):
```
export RECON_SCOPE_SECRET="your-secret-key-here"
python3 recon_agent.py example.com \
  --scope-file scope.json \
  --depth deep \
  --output-dir results/example.com
```

## Scan multiple targets from a file:

```python3 recon_agent.py --file targets.txt \
  --scope-file scope.json \
  --depth standard
```

## What Happens When You Run It

The script verifies the HMAC signature in scope.json.
It checks that your target(s) are in the allowed_targets list.

It shows the runtime acknowledgement prompt:

!!!!!!!!!!!!!!!!!!!!!!!!!!!
EXPLICIT AUTHORIZATION REQUIRED
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Type exactly: ""I ACKNOWLEDGE THIS SCAN IS AUTHORIZED AND WITHIN SCOPE""

→You must type that exact phrase to continue.

### If everything passes, the scan starts.