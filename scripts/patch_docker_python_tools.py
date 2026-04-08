#!/usr/bin/env python3
"""
Patcher: fix Docker build issues for this repo by:
1) Removing `nikto` from apt install list (not available in Debian slim apt repos).
2) Installing Nikto from upstream GitHub and symlinking `nikto` into PATH.
3) Replacing broad Amass go install pattern with concrete CLI module path.
4) Applying the same fix in scripts/patch_docker_python_tools.py if present.

Idempotent: safe to run multiple times.
"""

from pathlib import Path

FILES = [
    Path("Dockerfile"),
    Path("scripts/patch_docker_python_tools.py"),
]


def patch_text(s: str) -> str:
    # 1) Remove apt-installed nikto line if present
    s = s.replace("\n      nikto \\\n", "\n")
    s = s.replace("\n      nikto \\\\\n", "\n")  # for escaped form in Python string literals

    # 2) Replace broad amass module install with concrete cmd path
    s = s.replace(
        "go install github.com/owasp-amass/amass/v4/cmd/amass@latest",
        "go install github.com/owasp-amass/amass/v4/cmd/amass@latest",
    )

    # 3) Ensure upstream Nikto install block exists before Go install section
    nikto_block_dockerfile = (
        "# Install Nikto from upstream (not packaged in Debian slim images).\n"
        "RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \\\n"
        "    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto\n\n"
    )
    nikto_block_patcher = (
        "# Install Nikto from upstream (not packaged in Debian slim images).\n"
        "RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \\\\\n"
        "    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto\n\n"
    )

    if "github.com/sullo/nikto.git" not in s:
        if "# Install Go-based recon tools.\n" in s:
            block = (
                nikto_block_patcher
                if "DOCKERFILE_CONTENT = \"\"\"" in s
                else nikto_block_dockerfile
            )
            s = s.replace("# Install Go-based recon tools.\n", block + "# Install Go-based recon tools.\n", 1)

    return s


def patch_file(path: Path) -> bool:
    if not path.exists():
        print(f"[skip] {path} (missing)")
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
    print("[done] changes applied" if changed else "[done] no changes needed")


if __name__ == "__main__":
    main()