# Recon Agent Quick Start (v3.3)

## 1) Prerequisites

- Python 3.10+
- Linux/macOS/Windows shell access
- Recon binaries you plan to use (`nmap`, `amass`, `subfinder`, `nuclei`, etc.)
- A secret for scope signing

## 2) Install

```bash
pip install -r requirements.txt
```

## 3) Create signed scope

```bash
python3 create_scope.py
```

Or use the one-liner in `one-liner-scope-creation.md`.

## 4) Run

Single target:

```bash
export RECON_SCOPE_SECRET="your-secret-key"
python3 attack-surface-mapper.py example.com \
  --scope-file scope.json \
  --depth deep \
  --output-dir results/example.com
```

Multiple targets with scope auto-update:

```bash
python3 attack-surface-mapper.py --file targets.txt \
  --scope-file scope.json \
  --update-scope \
  --depth standard \
  --threads 12 \
  --output-dir results/batch
```

Optional: auto-install missing tools on Kali:

```bash
python3 attack-surface-mapper.py example.com \
  --scope-file scope.json \
  --depth standard \
  --auto-install
```

## 5) What the agent enforces

- Signed scope verification before execution
- Runtime explicit acknowledgement prompt
- Target filtering to in-scope assets only

## 6) Output structure

```
results/example.com/
├── findings.db
├── findings.jsonl
├── findings.csv
├── recon.log
└── raw_<target>_<tool>.txt
```

## 7) Troubleshooting

- **missing_scope_secret**: set `RECON_SCOPE_SECRET` or pass `--scope-secret`.
- **no_valid_targets_in_scope**: make sure targets are listed in `scope.json` and input files.
- **Missing tools**: install binaries manually or use `--auto-install` on Kali.
