# Using Signed Scope in Attack Surface Mapper

Signed scope is the authorization guardrail. The scanner only runs against targets listed in `scope.json` that has a valid HMAC-SHA256 signature.

As of v3.4, **all targets are canonicalized** (lowercased, stripped of schemes/ports, deduplicated, and sorted) before the signature is computed. This means `Example.com`, `https://example.com:443/path`, and `example.com` all resolve to the same canonical entry and produce the same signature.

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

```python
import json, hashlib, hmac

targets = [
    "example.com",
    "api.example.com",
    "192.168.1.0/24",
]
secret = "replace-with-strong-secret"

# Canonicalize: lowercase, sort, deduplicate (must match scanner logic)
canonical = sorted(set(t.strip().lower() for t in targets))

payload = json.dumps({"allowed_targets": canonical}, sort_keys=True).encode("utf-8")
signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

with open("scope.json", "w", encoding="utf-8") as f:
    json.dump({"allowed_targets": canonical, "signature": signature}, f, indent=2)
```

### Option C: One-liner

See `one-liner-scope-creation.md` for a single shell command version.

---

## Step 2: Run the scanner

```bash
export RECON_SCOPE_SECRET="your-secret"
python3 attack-surface-mapper.py example.com \
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
python3 attack-surface-mapper.py --file targets.txt \
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
HMAC-SHA256(secret, '{"allowed_targets": ["api.example.com", "example.com", "192.168.1.0/24"]}')
```

Canonicalization ensures that the signing tool (`create_scope.py`) and the scanner (`attack-surface-mapper.py`) always agree on the payload, regardless of how the operator originally formatted the targets.

If the signature doesn't match at scan time, the scanner aborts immediately before any tools are invoked.
