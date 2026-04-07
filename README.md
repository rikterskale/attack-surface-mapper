# Attack Surface Mapper

Attack Surface Mapper is a Python-based recon orchestrator that enforces a **signed scope file** before running third-party discovery/scanning tools.

## Features

- HMAC-signed scope enforcement (`scope.json`) before execution.
- Runtime explicit authorization acknowledgement.
- Async orchestration across passive/standard/deep tool sets.
- SQLite findings store with JSONL and CSV exports.
- Optional scope update + re-sign workflow.
- File logging to `recon.log` in the output directory.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Quick Start
Create a signed scope file:

python3 create_scope.py
Run a scan (recommended secret input method):

export RECON_SCOPE_SECRET="your-secret"
python3 attack-surface-mapper.py example.com \
  --scope-file scope.json \
  --depth standard \
  --output-dir results/example.com
--scope-secret is supported for compatibility but discouraged because CLI args may be visible in process listings.
```

External Tool Dependencies
The recon engine calls external binaries (for example: nmap, amass, subfinder, nuclei).
See external_tools.json for expected tools by scan depth.

You can optionally use:

```
python3 attack-surface-mapper.py example.com --scope-file scope.json --auto-install
(works only on Kali-like apt environments).
```

Output Artifacts
findings.db (SQLite)

findings.jsonl

findings.csv

recon.log

raw\_<target>\_<tool>.txt files per tool
