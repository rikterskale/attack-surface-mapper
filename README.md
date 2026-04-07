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
```

## Quick Start

Create a signed scope file:

```bash
python3 create_scope.py
```

Run a scan (recommended secret input method):

```bash
export RECON_SCOPE_SECRET="your-secret"
python3 attack-surface-mapper.py example.com \
  --scope-file scope.json \
  --depth standard \
  --output-dir results/example.com
```

> `--scope-secret` is supported for compatibility but discouraged because CLI args may be visible in process listings.

## Scan Depths

The `--depth` flag controls which tool categories run. Each deeper level adds its own tools — it does **not** include tools from shallower levels.

| Depth | Tools | Purpose |
|---|---|---|
| `passive` | amass, subfinder, assetfinder, knockpy, theharvester, sherlock | Subdomain enumeration and OSINT — no direct target interaction |
| `standard` | nmap, rustscan, naabu, whatweb, httpx, httprobe | Port scanning, service detection, HTTP probing |
| `deep` | nuclei, nikto, gobuster, feroxbuster, dirsearch | Vulnerability scanning and directory brute-forcing |

The authoritative tool-to-depth mapping is defined in `external_tools.json` and loaded at runtime by `PolicyEngine`.

## CLI Reference

```
attack-surface-mapper.py [target] [options]
```

| Flag | Description | Default |
|---|---|---|
| `target` (positional) | Single target domain/IP | — |
| `--file`, `-f` | Path to a file with one target per line | — |
| `--depth` | Scan depth: `passive`, `standard`, or `deep` | `standard` |
| `--output-dir`, `-o` | Directory for all output artifacts | `./recon_results` |
| `--threads`, `-t` | Max concurrent tool executions | `8` |
| `--retries` | Number of retries per tool on failure | `2` |
| `--scope-file` | **(required)** Path to signed `scope.json` | — |
| `--scope-secret` | Scope HMAC secret (prefer `RECON_SCOPE_SECRET` env var) | — |
| `--update-scope` | Merge targets from `--file` into scope and re-sign before scanning | off |
| `--policy` | Path to a policy JSON override file for `PolicyEngine` | — |
| `--auto-install` | Attempt `apt install` of missing tools (Kali Linux only) | off |
| `--verbose`, `-v` | Print full tracebacks on unexpected errors | off |

## Signed-Scope and Runtime Acknowledgement

Every scan requires two authorization gates:

1. **Signed scope file** — `scope.json` contains an `allowed_targets` list and an HMAC-SHA256 `signature` computed over the canonicalized target list using a shared secret. The agent verifies this signature before proceeding. Use `create_scope.py` (or the one-liner in `one-liner-scope-creation.md`) to generate and sign the file. Use `--update-scope` with `--file` to merge new targets and re-sign automatically.

2. **Runtime acknowledgement** — Before execution the operator must type an exact confirmation string at the interactive prompt. This prevents unattended or accidental scans. The mechanism is implemented in `ScopeValidator.runtime_acknowledgement()`.

Together these ensure that (a) the target list has not been tampered with, and (b) a human operator explicitly authorizes each run. See `signed_scope_howto.md` for a detailed walkthrough.

## External Tool Dependencies

The recon engine calls external binaries. See `external_tools.json` for the expected tools by scan depth.

Auto-install on Kali-like systems:

```bash
python3 attack-surface-mapper.py example.com --scope-file scope.json --auto-install
```

## Output Artifacts

All outputs are written to the directory specified by `--output-dir`.

| File | Format | Description |
|---|---|---|
| `findings.db` | SQLite | Primary data store. Single table `findings` with columns: `id` (TEXT PK), `tool`, `asset`, `indicator`, `value`, `type`, `severity`, `confidence` (REAL), `timestamp`, `correlated_to` (JSON array as TEXT). |
| `findings.jsonl` | JSON Lines | One JSON object per line, same columns as the SQLite table. |
| `findings.csv` | CSV | Header row matching the SQLite columns, one finding per row. |
| `recon.log` | Structured JSON log | Append-only structured log (one JSON object per line) from `structlog`. |
| `raw_<target>_<tool>.txt` | Plain text | Raw stdout captured from each tool execution. |
