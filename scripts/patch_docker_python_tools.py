#!/usr/bin/env python3
"""Patch Docker assets so the image ships Python + recon tooling by default.

This script is idempotent: running it repeatedly keeps the same desired content.
"""

from pathlib import Path

DOCKERFILE = Path("Dockerfile")
HOWTO = Path("Docker_HOWTO.md")

DOCKERFILE_CONTENT = """FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    GO111MODULE=on \\
    GOBIN=/usr/local/bin

WORKDIR /app

# Install system and language toolchains used by recon tools.
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
      ca-certificates \\
      curl \\
      git \\
      golang-go \\
      gobuster \\
      nikto \\
      nmap \\
      unzip \\
      whatweb && \\
    rm -rf /var/lib/apt/lists/*

# Install Go-based recon tools.
RUN go install github.com/owasp-amass/amass/v4/...@latest && \\
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \\
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \\
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \\
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \\
    go install github.com/tomnomnom/assetfinder@latest && \\
    go install github.com/tomnomnom/httprobe@latest

# Install Python-based recon tools plus this project and dev tooling.
COPY . .
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel && \\
    python -m pip install --no-cache-dir \\
      dirsearch \\
      knockpy \\
      sherlock-project \\
      theHarvester && \\
    python -m pip install --no-cache-dir -e ".[dev]" && \\
    python --version && \\
    pip --version && \\
    ruff --version && \\
    mypy --version && \\
    pytest --version && \\
    amass -version && \\
    nuclei -version && \\
    nmap --version

# Default command shows CLI help.
CMD ["python", "attack_surface_mapper.py", "--help"]
"""

HOWTO_CONTENT = """# Docker How-To Guide (Beginner Friendly)

This guide explains how to build and run **Attack Surface Mapper** with Docker from scratch.

---

## 1) What Docker does here

Docker packages:
- The app + Python dependencies
- Python dev tools (`pip`, `ruff`, `mypy`, `pytest`)
- Common external recon tools used by this project, including `amass`, `subfinder`, `assetfinder`, `nmap`, `naabu`, `httpx`, `nuclei`, `nikto`, `gobuster`, `whatweb`, `httprobe`, and Python-based tools (`knockpy`, `theHarvester`, `sherlock`, `dirsearch`)

So to your question: **yes, the image is now configured to include tools like `amass`, `nuclei`, and `nmap` by default**.

---

## 2) Prerequisites

Install Docker Desktop (Windows/macOS) or Docker Engine (Linux), then verify:

```bash
docker --version
docker info
```

If `docker info` fails, make sure Docker is running.

---

## 3) Build the image

From the repository root:

```bash
docker build -t attack-surface-mapper:latest .
```

What this does:
- Uses `Dockerfile`
- Installs system packages needed for external recon binaries
- Installs Go-based recon binaries (`amass`, `subfinder`, `naabu`, `httpx`, `nuclei`, etc.)
- Installs Python-based recon tools (`knockpy`, `theHarvester`, `sherlock`, `dirsearch`)
- Installs project dependencies and Python dev tooling via `pip install -e ".[dev]"`

---

## 4) Verify included toolchain

Run these checks after build:

```bash
docker run --rm attack-surface-mapper:latest python --version
docker run --rm attack-surface-mapper:latest pip --version
docker run --rm attack-surface-mapper:latest ruff --version
docker run --rm attack-surface-mapper:latest mypy --version
docker run --rm attack-surface-mapper:latest pytest --version

docker run --rm attack-surface-mapper:latest amass -version
docker run --rm attack-surface-mapper:latest nuclei -version
docker run --rm attack-surface-mapper:latest nmap --version
```

---

## 5) Quick sanity check

Show help text from inside container:

```bash
docker run --rm attack-surface-mapper:latest
```

or explicitly:

```bash
docker run --rm attack-surface-mapper:latest python attack_surface_mapper.py --help
```

---

## 6) Create signed scope from container

Interactive scope creation (writes file to your host directory):

```bash
docker run --rm -it \\
  -v "$(pwd):/work" \\
  -w /work \\
  attack-surface-mapper:latest \\
  python create_scope.py
```

This creates `scope.json` in your current host folder.

---

## 7) Run scanner from container

Example run:

```bash
docker run --rm -it \\
  -v "$(pwd):/work" \\
  -w /work \\
  -e RECON_SCOPE_SECRET="your-secret-min-16-chars" \\
  attack-surface-mapper:latest \\
  python attack_surface_mapper.py example.com \\
    --scope-file scope.json \\
    --depth passive \\
    --output-dir results/example.com
```

Notes:
- `-v "$(pwd):/work"` mounts your current folder so outputs persist on host.
- `-e RECON_SCOPE_SECRET=...` passes secret without CLI argument exposure.

---

## 8) Running non-interactive in CI-like mode

If you need to bypass the acknowledgement prompt intentionally:

```bash
docker run --rm \\
  -v "$(pwd):/work" \\
  -w /work \\
  -e RECON_SCOPE_SECRET="your-secret-min-16-chars" \\
  -e RECON_UNATTENDED=1 \\
  attack-surface-mapper:latest \\
  python attack_surface_mapper.py example.com \\
    --scope-file scope.json \\
    --depth passive \\
    --no-ack
```

Both `RECON_UNATTENDED=1` and `--no-ack` are required.

---

## 9) Common troubleshooting

### A) `scope.json not found`
- Ensure your host directory is mounted (`-v "$(pwd):/work"`).
- Ensure `--scope-file` path is correct inside container.

### B) Permission errors writing outputs
- Verify mounted directory permissions.
- Try writing to a mounted folder you own.

### C) `missing_scope_secret`
- Pass `RECON_SCOPE_SECRET` with `-e`.

### D) Docker build fails due network
- Retry on stable network.
- Use internal package mirror/proxy if required by your environment.

---

## 10) Useful cleanup commands

Remove dangling images:

```bash
docker image prune -f
```

Remove all stopped containers:

```bash
docker container prune -f
```

---

## 11) CI integration note

The GitHub Actions workflow includes a Docker build job that executes:

```bash
docker build -t attack-surface-mapper:ci .
```

This validates that the Docker image can be built on every push/PR.
"""


def _write_if_changed(path: Path, content: str) -> None:
    if path.read_text(encoding="utf-8") != content:
        path.write_text(content, encoding="utf-8")
        print(f"[updated] {path}")
    else:
        print(f"[ok] {path} already up-to-date")


def main() -> None:
    _write_if_changed(DOCKERFILE, DOCKERFILE_CONTENT)
    _write_if_changed(HOWTO, HOWTO_CONTENT)


if __name__ == "__main__":
    main()
