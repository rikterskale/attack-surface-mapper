# Docker How-To Guide (Beginner Friendly)

This guide explains how to build and run **Attack Surface Mapper** with Docker from scratch.

---

## 1) What Docker does here

Docker packages the app and its Python dependencies into an image so you can run it consistently across machines.

> Important: This image includes the Python app and library dependencies. Most external recon binaries (`nmap`, `amass`, `subfinder`, etc.) are still host/container tool dependencies and may not be installed in the image by default.

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
- Installs Python deps
- Copies project files
- Sets default command to show CLI help

---

## 4) Quick sanity check

Show help text from inside container:

```bash
docker run --rm attack-surface-mapper:latest
```

or explicitly:

```bash
docker run --rm attack-surface-mapper:latest python attack_surface_mapper.py --help
```

---

## 5) Create signed scope from container

Interactive scope creation (writes file to your host directory):

```bash
docker run --rm -it \
  -v "$(pwd):/work" \
  -w /work \
  attack-surface-mapper:latest \
  python create_scope.py
```

This creates `scope.json` in your current host folder.

---

## 6) Run scanner from container

Example run:

```bash
docker run --rm -it \
  -v "$(pwd):/work" \
  -w /work \
  -e RECON_SCOPE_SECRET="your-secret-min-16-chars" \
  attack-surface-mapper:latest \
  python attack_surface_mapper.py example.com \
    --scope-file scope.json \
    --depth passive \
    --output-dir results/example.com
```

Notes:
- `-v "$(pwd):/work"` mounts your current folder so outputs persist on host.
- `-e RECON_SCOPE_SECRET=...` passes secret without CLI argument exposure.

---

## 7) Running non-interactive in CI-like mode

If you need to bypass the acknowledgement prompt intentionally:

```bash
docker run --rm \
  -v "$(pwd):/work" \
  -w /work \
  -e RECON_SCOPE_SECRET="your-secret-min-16-chars" \
  -e RECON_UNATTENDED=1 \
  attack-surface-mapper:latest \
  python attack_surface_mapper.py example.com \
    --scope-file scope.json \
    --depth passive \
    --no-ack
```

Both `RECON_UNATTENDED=1` and `--no-ack` are required.

---

## 8) External tool availability

The scanner can call third-party tools. If they are not installed in the image, the app logs warnings and skips them.

For a fully tooled image, you can extend the Dockerfile later to install specific binaries needed by your workflow.

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
