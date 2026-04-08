#!/usr/bin/env python3
"""
Patcher for Docker Go-install build failures.

What it changes:
1) Rewrites the Go tool install RUN block in Dockerfile to "best effort"
   so a single upstream/toolchain break does not fail the whole image build.
2) Applies the same change inside scripts/patch_docker_python_tools.py so
   future generated Dockerfiles keep the fix.

Usage:
  python patch_go_install_failures.py
"""

from pathlib import Path

TARGETS = [
    Path("Dockerfile"),
    Path("scripts/patch_docker_python_tools.py"),
]

OLD_BLOCK_DOCKERFILE = """# Install Go-based recon tools (best effort; do not fail entire image build).
RUN set -eux; \\
    for pkg in \\
      github.com/owasp-amass/amass/v4/cmd/amass@latest \\
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \\
      github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \\
      github.com/projectdiscovery/httpx/cmd/httpx@latest \\
      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \\
      github.com/tomnomnom/assetfinder@latest \\
      github.com/tomnomnom/httprobe@latest; do \\
        if ! go install "$pkg"; then \\
          echo "WARN: failed to install $pkg (continuing)"; \\
        fi; \\
    done
"""

NEW_BLOCK_DOCKERFILE = """# Install Go-based recon tools (best effort; do not fail entire image build).
RUN set -eux; \\
    for pkg in \\
      github.com/owasp-amass/amass/v4/cmd/amass@latest \\
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \\
      github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \\
      github.com/projectdiscovery/httpx/cmd/httpx@latest \\
      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \\
      github.com/tomnomnom/assetfinder@latest \\
      github.com/tomnomnom/httprobe@latest; do \\
        if ! go install "$pkg"; then \\
          echo "WARN: failed to install $pkg (continuing)"; \\
        fi; \\
    done
"""

# Same strings but escaped as they'd appear in the Python patcher's DOCKERFILE_CONTENT literal.
OLD_BLOCK_PATCHER = OLD_BLOCK_DOCKERFILE.replace("\\", "\\\\")
NEW_BLOCK_PATCHER = NEW_BLOCK_DOCKERFILE.replace("\\", "\\\\")


def patch_file(path: Path) -> bool:
    if not path.exists():
        print(f"[skip] {path} (missing)")
        return False

    text = path.read_text(encoding="utf-8")
    original = text

    # First try exact replacement for Dockerfile form.
    text = text.replace(OLD_BLOCK_DOCKERFILE, NEW_BLOCK_DOCKERFILE)

    # Then replace inside Python patcher template form.
    text = text.replace(OLD_BLOCK_PATCHER, NEW_BLOCK_PATCHER)

    # Fallback: if amass line exists but block differs slightly, inject best-effort wrapper.
    if (
        "go install github.com/owasp-amass/amass/v4/cmd/amass@latest" in text
        and "best effort; do not fail entire image build" not in text
    ):
        # naive but safe fallback for minor formatting drifts
        start = text.find("# Install Go-based recon tools.")
        if start != -1:
            end = text.find("\n\n# Install Python-based recon tools", start)
            if end != -1:
                replacement = (
                    NEW_BLOCK_DOCKERFILE
                    if path.name == "Dockerfile"
                    else NEW_BLOCK_PATCHER
                )
                text = text[:start] + replacement + text[end:]

    if text != original:
        path.write_text(text, encoding="utf-8")
        print(f"[updated] {path}")
        return True

    print(f"[ok] {path} already patched")
    return False


def main() -> None:
    changed = False
    for path in TARGETS:
        changed |= patch_file(path)
    print("[done] patch applied" if changed else "[done] no changes needed")


if __name__ == "__main__":
    main()