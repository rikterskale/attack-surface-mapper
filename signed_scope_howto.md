# Using Signed Scope in Attack Surface Mapper

Signed scope is the authorization guardrail. The scanner only runs against targets listed in `scope.json` that has a valid HMAC-SHA256 signature.

As of v3.4.0, **all targets are canonicalized** (lowercased, stripped of schemes/ports, CIDR preserved, deduplicated, and sorted) before the signature is computed. This means `Example.com`, `https://example.com:443/path`, and `example.com` all resolve to the same canonical entry and produce the same signature. CIDR ranges like `192.168.1.0/24` are preserved as network notation.

---

## Step 1: Create `scope.json`

### Option A: Use the bundled helper (recommended)

```bash
python3 create_scope.py example.com api.example.com 192.168.1.0/24
```

Or run it with no arguments to use the built-in default target list:

```bash
python3 create_scope.py
```

You can also specify an output path:

```bash
python3 create_scope.py -o scopes/prod_scope.json example.com api.example.com
```

### Option B: Create it manually in Python

> **Important:** This snippet imports `scope_utils` to ensure identical canonicalization with the scanner. Run it from the project directory.

```python
import json
from scope_utils import canonicalize_targets, compute_signature, validate_secret

targets = [
    "example.com",
    "api.example.com",
    "192.168.1.0/24",
]
secret = input("Enter secret key (min 16 chars): ").strip()
validate_secret(secret)

canonical = canonicalize_targets(targets)
signature = compute_signature(canonical, secret)

with open("scope.json", "w", encoding="utf-8") as f:
    json.dump({"allowed_targets": canonical, "signature": signature}, f, indent=2)

print("scope.json created")
```

### Option C: One-liner

See `one-liner-scope-creation.md` for a single shell command version.

---

## Step 2: Run the scanner

```bash
export RECON_SCOPE_SECRET="your-secret-min-16-chars"
python3 attack_surface_mapper.py example.com \
  --scope-file scope.json \
  --depth standard \
  --output-dir results/example.com
```

The scanner will:

1. Verify the HMAC signature of `scope.json` against `RECON_SCOPE_SECRET`.
2. Prompt for explicit runtime acknowledgement.
3. Only then begin scanning targets that appear in the verified scope.

---

## Step 3: Optional scope update from file

```bash
python3 attack_surface_mapper.py --file targets.txt \
  --scope-file scope.json \
  --update-scope \
  --depth passive
```

The `--update-scope` flag will:

- Read targets from the file specified by `--file`.
- Canonicalize and validate each target.
- Merge valid entries into the existing `scope.json`.
- Re-sign the scope with the same secret.
- Skip and log any invalid targets.

---

## How the signature works

The HMAC-SHA256 signature is computed over a JSON payload containing the **canonicalized** target list:

```
HMAC-SHA256(secret, '{"allowed_targets": ["192.168.1.0/24", "api.example.com", "example.com"]}')
```

Canonicalization ensures that the signing tool (`create_scope.py`) and the scanner (`attack_surface_mapper.py`) always agree on the payload, regardless of how the operator originally formatted the targets. Both import their canonicalization logic from `scope_utils.py`.

If the signature doesn't match at scan time, the scanner aborts immediately before any tools are invoked.
