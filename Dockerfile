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

# Install Go-based recon tools.
RUN go install github.com/owasp-amass/amass/v4/cmd/amass@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/httprobe@latest

# Install Python-based recon tools plus this project and dev tooling.
COPY . .
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python -m pip install --no-cache-dir \
      dirsearch \
      knockpy \
      sherlock-project \
      theHarvester && \
    python -m pip install --no-cache-dir -e ".[dev]" && \
    python --version && \
    pip --version && \
    ruff --version && \
    mypy --version && \
    pytest --version && \
    amass -version && \
    nuclei -version && \
    nmap --version

# Default command shows CLI help.
CMD ["python", "attack_surface_mapper.py", "--help"]
