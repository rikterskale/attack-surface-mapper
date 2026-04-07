# Recon Agent Quick Start Guide (v3.2)
## Enterprise-grade OSINT & reconnaissance tool
## Supports passive, standard, and deep modes with 15+ industry tools.

## 1. Prerequisites

Python 3.10+
Kali Linux (recommended) or Windows
Basic command-line tools (amass, subfinder, nuclei, etc.) — the script can auto-detect missing ones
A strong secret key for scope signing


## 2. Installation

Save the full script as recon_agent.py

Install required Python packages:
```
pip install structlog tqdm opentelemetry-api opentelemetry-sdk pydantic
```

### (Optional) Make the script executable:
```
chmod +x recon_agent.py
```

## 3. Create Your Signed scope.json (One-Liner)

### Run this single command to create a signed scope file:
```
python3 -c '
import json, hashlib, hmac, sys
print("=== Recon Agent - Signed Scope Creator ===\n")
targets = [
    "example.com",
    "api.example.com",
    "192.168.1.0/24"
]
secret = input("Enter a strong secret key (keep it safe!): ").strip()
if len(secret) < 8:
    print("❌ Secret too short")
    sys.exit(1)
payload = json.dumps({"allowed_targets": targets}, sort_keys=True).encode()
signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
with open("scope.json", "w", encoding="utf-8") as f:
    json.dump({"allowed_targets": targets, "signature": signature}, f, indent=2)
print("✅ scope.json created successfully!")
print(f"   Authorized targets: {len(targets)}")
'
```

### Tip: Edit the targets = [...] list before running the command.

## 4. Running the Recon Agent
### Recommended Secure Way (no secret in history)
```
export RECON_SCOPE_SECRET="your-secret-key-here"
```

## Basic Commands
### Single Target
```
python3 recon_agent.py example.com \
  --scope-file scope.json \
  --depth deep \
  --output-dir results/example.com
```

### Multiple Targets from File (with automatic scope update)
```
python3 recon_agent.py --file targets.txt \
  --scope-file scope.json \
  --update-scope \          # ← automatically adds new targets + re-signs
  --depth standard \
  --threads 12 \
  --output-dir results/batch
```

### All Available Options (most useful)
```
python3 recon_agent.py --help

Key flags:

--file targets.txt → scan many targets
--update-scope → merge targets.txt into scope.json and re-sign
--depth passive|standard|deep
--threads 12 → concurrency control
--retries 3 → retry on failure
--verbose → extra debug output
```

## 5. What Happens When You Run It

### Authorization Guardrails
### Verifies scope.json signature
### Checks your targets are in the allowed list
### Shows big runtime acknowledgement prompt (you must type the exact phrase)

### Scope Auto-Update (if --update-scope is used)

### Reads targets.txt
### Adds any new valid targets
### Re-signs scope.json
### Logs every step with detailed JSON logs

### Scan Execution
### Runs only policy-allowed tools
### Parallel execution with controlled concurrency
### Real-time structured JSON logging + OpenTelemetry traces
### Saves raw output, SQLite DB, JSONL, CSV, etc.

## Final Summary
#### Prints clean human-readable report + full JSON

## 6. Output Directory Structure
### textresults/example.com/
   ### ├── findings.db          # SQLite database
   ### ├── findings.jsonl       # Machine-readable line-by-line findings
   ### ├── findings.csv         # Spreadsheet-friendly export
   ### ├── recon.log            # Structured JSON logs
   ### ├── raw_example.com_amass.txt
   ### ├── raw_example.com_nuclei.txt
   ### └── ... (one raw file per tool)

## 7. Troubleshooting & Common Issues

##  Issue                      Solution 
### missing_scope_secret       Set export RECON_SCOPE_SECRET=... or use --scope-secret
### Scope update failed        Check file permissions on scope.json
### Invalid target format      Only domains, IPs, or CIDR ranges are allowed
### Tool not found             Run with --auto-install (future versions) or install manually
### no_valid_targets_in_scope  Target must exist in both targets.txt and scope.json

###Enable full debug logging:
```
python3 recon_agent.py ... --verbose
```

## 8. Quick Example Workflow (Copy-Paste)
### 1. Create scope
``
python3 -c '...'   # (use the one-liner above)
``

### 2. Set secret
export RECON_SCOPE_SECRET="MySuperSecret123!"

### 3. Run full scan with auto-update
```
python3 recon_agent.py --file targets.txt \
  --scope-file scope.json \
  --update-scope \
  --depth deep \
  --threads 12 \
  --output-dir results/batch-scan
```

## You’re ready to go!
## The agent is now production-ready with enterprise guardrails, detailed error logging, and automatic scope management.