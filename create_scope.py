#!/usr/bin/env python3
import json
import hashlib
import hmac
import sys

print("=== Recon Agent - Create Signed Scope ===\n")

# === EDIT THIS LIST ===
targets = [
    "example.com",
    "api.example.com",
    "test.example.com",
    "192.168.1.0/24",      # you can use CIDR ranges too
    # Add as many domains/IPs as you want
]

secret = input("Enter a strong secret key (keep this safe!): ").strip()
if len(secret) < 8:
    print("❌ Secret must be at least 8 characters.")
    sys.exit(1)

# Create the payload and HMAC signature
payload = json.dumps({"allowed_targets": targets}, sort_keys=True).encode("utf-8")
signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

scope_data = {
    "allowed_targets": targets,
    "signature": signature
}

with open("scope.json", "w", encoding="utf-8") as f:
    json.dump(scope_data, f, indent=2)

print("\n✅ scope.json created successfully!")
print(f"   Targets authorized: {len(targets)}")
print(f"   Signature: {signature[:16]}... (full signature saved in file)")
print("\nKeep your secret key safe — you'll need it to run the agent.")