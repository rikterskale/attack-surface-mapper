# Recon Agent Quick Start (v3.4.0)

## 1) Prerequisites

- Python 3.10+
- Linux/macOS/Windows shell access
- Recon binaries you plan to use (`nmap`, `amass`, `subfinder`, `nuclei`, etc.)
- A secret for scope signing (minimum 16 characters)

## 2) Install

Runtime-only install:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you plan to run lint/typecheck/tests locally, use dev install instead:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## 3) Create signed scope

Pass targets directly on the command line:

```bash
python3 create_scope.py example.com api.example.com 192.168.1.0/24
```

Or run with no arguments to use the built-in default list:

```bash
python3 create_scope.py
```

You can also use the one-liner in `one-liner-scope-creation.md`.

## 4) Run

Single target (passive — no direct target interaction):

```bash
export RECON_SCOPE_SECRET="your-secret-min-16-chars"
python3 attack_surface_mapper.py example.com \
  --scope-file scope.json \
  --depth passive \
  --output-dir results/example.com
```

Multiple targets with scope auto-update:

```bash
python3 attack_surface_mapper.py --file targets.txt \
  --scope-file scope.json \
  --update-scope \
  --depth standard \
  --threads 12 \
  --output-dir results/batch
```

Optional: auto-install missing tools on Kali:

```bash
python3 attack_surface_mapper.py example.com \
  --scope-file scope.json \
  --depth standard \
  --auto-install
```

## 5) What the agent enforces

1. **Signed scope verification** — the HMAC signature on `scope.json` is verified before anything else.
2. **Minimum secret length** — the secret must be at least 16 characters.
3. **Runtime acknowledgement prompt** — the operator must type an exact confirmation string.
4. **Target filtering** — only targets present in the verified scope are scanned.

## 6) Output structure

```
results/example.com/
├── findings.db            # SQLite findings store
├── findings.jsonl         # JSON Lines export
├── findings.csv           # CSV export
├── recon.log              # Structured JSON log
├── spans.jsonl            # OpenTelemetry trace spans
└── example_com/           # Per-target subdirectory
    ├── raw_example_com_nmap.txt
    ├── raw_example_com_subfinder.txt
    └── ...
```

Top-level files (`findings.*`, `recon.log`, `spans.jsonl`) live in the output directory. Raw tool output goes into per-target subdirectories named after the sanitized target.

## 7) Troubleshooting

- **missing_scope_secret**: set `RECON_SCOPE_SECRET` or pass `--scope-secret`.
- **scope_secret_too_short**: secret must be at least 16 characters.
- **no_valid_targets_in_scope**: make sure targets are listed in `scope.json` and match your input. Targets are canonicalized (lowercased, schemes/ports stripped, CIDR preserved) — `Example.com` and `https://example.com:443` both resolve to `example.com`.
- **Invalid scope signature**: if you edited `scope.json` by hand or changed your secret, re-run `create_scope.py` to regenerate it.
- **Missing tools**: install binaries manually or use `--auto-install` on Kali. The scanner logs a warning for each missing tool so you can see exactly what was skipped.
