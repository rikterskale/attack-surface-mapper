FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GO111MODULE=on \
    GOBIN=/usr/local/bin

WORKDIR /app

# Install system and language toolchains used by recon tools.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      golang-go \
      gobuster \
      nmap \
      unzip \
      whatweb && \
    rm -rf /var/lib/apt/lists/*

# Install Nikto from upstream (not packaged in Debian slim images).
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Install Go-based recon tools (best effort; do not fail entire image build).
RUN set -eux; \
    for pkg in \
      github.com/owasp-amass/amass/v4/cmd/amass@latest \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
      github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
      github.com/projectdiscovery/httpx/cmd/httpx@latest \
      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
      github.com/tomnomnom/assetfinder@latest \
      github.com/tomnomnom/httprobe@latest; do \
        if ! go install "$pkg"; then \
          echo "WARN: failed to install $pkg (continuing)"; \
        fi; \
    done

# Install Python-based recon tools plus this project and dev tooling.
COPY . .
RUN set -eux; \
    python -m pip install --no-cache-dir --upgrade pip setuptools wheel; \
    for pkg in dirsearch knockpy sherlock-project theHarvester; do \
      if ! python -m pip install --no-cache-dir "$pkg"; then \
        echo "WARN: failed to install Python recon package $pkg (continuing)"; \
      fi; \
    done; \
    python -m pip install --no-cache-dir -e ".[dev]"; \
    python --version; \
    pip --version; \
    ruff --version; \
    mypy --version; \
    pytest --version; \
    for cmd in amass nuclei nmap; do \
      if command -v "$cmd" >/dev/null 2>&1; then \
        "$cmd" --version || "$cmd" -version || true; \
      else \
        echo "WARN: $cmd not found in PATH (continuing)"; \
      fi; \
    done

# Default command shows CLI help.
CMD ["python", "attack_surface_mapper.py", "--help"]
