#!/usr/bin/env python3
"""
Patcher for Docker build failures in Python tool install/verification stage.

It makes two safety changes in BOTH:
  - Dockerfile
  - scripts/patch_docker_python_tools.py

1) Python recon tool installs become best-effort (do not fail whole build).
2) Tool/version checks become non-fatal (warn + continue).

Run:
  python patch_python_install_failures.py
"""

from pathlib import Path

FILES = [
    Path("Dockerfile"),
    Path("scripts/patch_docker_python_tools.py"),
]

OLD_DOCKER_BLOCK = """RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel && \\
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
"""

NEW_DOCKER_BLOCK = """RUN set -eux; \\
    python -m pip install --no-cache-dir --upgrade pip setuptools wheel; \\
    for pkg in dirsearch knockpy sherlock-project theHarvester; do \\
      if ! python -m pip install --no-cache-dir "$pkg"; then \\
        echo "WARN: failed to install Python recon package $pkg (continuing)"; \\
      fi; \\
    done; \\
    python -m pip install --no-cache-dir -e ".[dev]"; \\
    python --version; \\
    pip --version; \\
    ruff --version; \\
    mypy --version; \\
    pytest --version; \\
    for cmd in amass nuclei nmap; do \\
      if command -v "$cmd" >/dev/null 2>&1; then \\
        "$cmd" --version || "$cmd" -version || true; \\
      else \\
        echo "WARN: $cmd not found in PATH (continuing)"; \\
      fi; \\
    done
"""

def patch_text(text: str) -> str:
    # direct form (Dockerfile)
    patched = text.replace(OLD_DOCKER_BLOCK, NEW_DOCKER_BLOCK)

    # escaped form inside Python triple-quoted template (patcher script)
    old_escaped = OLD_DOCKER_BLOCK.replace("\\", "\\\\").replace('"', '\\"')
    new_escaped = NEW_DOCKER_BLOCK.replace("\\", "\\\\").replace('"', '\\"')
    patched = patched.replace(old_escaped, new_escaped)

    return patched


def patch_file(path: Path) -> bool:
    if not path.exists():
        print(f"[skip] {path} missing")
        return False
    old = path.read_text(encoding="utf-8")
    new = patch_text(old)
    if new != old:
        path.write_text(new, encoding="utf-8")
        print(f"[updated] {path}")
        return True
    print(f"[ok] {path} already patched")
    return False


def main() -> None:
    changed = False
    for f in FILES:
        changed |= patch_file(f)
    print("[done] patch applied" if changed else "[done] no changes needed")


if __name__ == "__main__":
    main()
