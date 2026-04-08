#!/usr/bin/env python3
from pathlib import Path

DOCKERFILE = Path("Dockerfile")
HOWTO = Path("Docker_HOWTO.md")


def patch_dockerfile() -> bool:
    if not DOCKERFILE.exists():
        print("[skip] Dockerfile not found")
        return False

    s = DOCKERFILE.read_text(encoding="utf-8")
    original = s

    # 1) Remove `nikto` from apt install list (if present)
    s = s.replace("\n      nikto \\\n", "\n")

    # 2) Add upstream Nikto install block (if missing)
    nikto_block = (
        "# Install Nikto from upstream (not packaged in Debian slim images).\n"
        "RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \\\n"
        "    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto\n\n"
    )
    anchor = "# Install Go-based recon tools.\n"
    if "github.com/sullo/nikto.git" not in s and anchor in s:
        s = s.replace(anchor, nikto_block + anchor, 1)

    if s != original:
        DOCKERFILE.write_text(s, encoding="utf-8")
        print("[updated] Dockerfile")
        return True

    print("[ok] Dockerfile already patched")
    return False


def patch_howto() -> bool:
    if not HOWTO.exists():
        print("[skip] Docker_HOWTO.md not found")
        return False

    s = HOWTO.read_text(encoding="utf-8")
    original = s

    old_line = (
        "- Installs system packages needed for external recon binaries\n"
    )
    new_line = (
        "- Installs system packages needed for external recon binaries and installs Nikto from upstream GitHub\n"
    )
    s = s.replace(old_line, new_line)

    # Add explanatory note if not already present
    note_snippet = "nikto` is installed from its upstream GitHub repo"
    if note_snippet not in s and "## 1) What Docker does here" in s:
        s = s.replace(
            "So to your question: **yes, the image is now configured to include tools like `amass`, `nuclei`, and `nmap` by default**.\n",
            "So to your question: **yes, the image is now configured to include tools like `amass`, `nuclei`, and `nmap` by default**.\n\n"
            "> Note: `nikto` is installed from its upstream GitHub repository in this image because it is not available as an apt package in the base Debian slim image.\n",
            1,
        )

    if s != original:
        HOWTO.write_text(s, encoding="utf-8")
        print("[updated] Docker_HOWTO.md")
        return True

    print("[ok] Docker_HOWTO.md already patched")
    return False


def main() -> None:
    changed = False
    changed |= patch_dockerfile()
    changed |= patch_howto()
    if changed:
        print("[done] Patch applied")
    else:
        print("[done] No changes needed")


if __name__ == "__main__":
    main()