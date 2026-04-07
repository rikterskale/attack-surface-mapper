README.md
# Attack Surface Mapper

Attack Surface Mapper is a Python-based recon orchestrator that enforces a signed scope file before running third-party discovery/scanning tools.

## What it does

- Validates `scope.json` using HMAC-SHA256 before any scan starts.
- Requires runtime authorization acknowledgement from the operator.
- Runs policy-allowed tools asynchronously (`passive`, `standard`, `deep`).
- Stores findings in SQLite and exports JSONL + CSV.
- Supports scope updates with re-signing via `--update-scope`.

## Quick start

1. Install Python dependencies:

```bash
pip install -r requirements.txt
Create a signed scope file:

python3 create_scope.py
Run a scan:

export RECON_SCOPE_SECRET="your-secret"
python3 attack-surface-mapper.py example.com \
  --scope-file scope.json \
  --depth standard \
  --output-dir results/example.com
External tool dependencies
The recon engine calls external binaries (for example: nmap, amass, subfinder, nuclei, etc.).

See external_tools.json for the expected tool list per scan depth.

Use --auto-install on Kali Linux to attempt apt-based install of missing tools.

Output artifacts
findings.db (SQLite)

findings.jsonl

findings.csv

raw_<target>_<tool>.txt per tool

Safety note
Only scan assets you are explicitly authorized to test.


---



