## One-liner signed scope creation

Run this command from the project directory (where `scope_utils.py` lives) and edit the `targets` list inline before executing:

```
python3 -c '
import json, getpass, sys
from scope_utils import canonicalize_targets, compute_signature, validate_secret
print("=== Signed Scope Creator ===\n")
targets = ["example.com", "api.example.com", "192.168.1.0/24"]
secret = getpass.getpass("Enter secret key (min 16 chars): ").strip()
validate_secret(secret)
canonical = canonicalize_targets(targets)
signature = compute_signature(canonical, secret)
with open("scope.json", "w", encoding="utf-8") as f:
    json.dump({"allowed_targets": canonical, "signature": signature}, f, indent=2)
print("scope.json created")
'
```

Keep the secret safe; you need it as `RECON_SCOPE_SECRET` (or `--scope-secret`) when running the scanner.
