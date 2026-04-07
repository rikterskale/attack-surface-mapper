#!/usr/bin/env python3
"""
Create a signed scope file (scope.json) for Attack Surface Mapper v3.4.

Targets are canonicalized (lowercased, stripped, deduplicated, sorted) before
signing so the HMAC matches regardless of how the operator formats them.
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Target validation — mirrors parse_and_canonicalize_target() in the scanner
# ---------------------------------------------------------------------------

_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
)


def canonicalize_target(target: str) -> str:
    """Normalize a target to the same canonical form the scanner uses."""
    target = target.strip().lower()
    if "://" in target:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    target = target.rstrip("/").split("/", 1)[0]
    if ":" in target and not target.startswith("["):
        host, port = target.rsplit(":", 1)
        if port.isdigit():
            target = host

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    if _DOMAIN_REGEX.match(target):
        return target
    raise ValueError(f"Invalid target format: {target}")


def canonicalize_all(targets: list[str]) -> list[str]:
    """Canonicalize, deduplicate, and sort a list of targets."""
    results: list[str] = []
    for t in targets:
        try:
            results.append(canonicalize_target(t))
        except ValueError:
            pass
    return sorted(set(results))


def compute_signature(targets: list[str], secret: str) -> str:
    """Compute HMAC-SHA256 over canonicalized, sorted targets."""
    canonical = canonicalize_all(targets)
    payload = json.dumps({"allowed_targets": canonical}, sort_keys=True).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

MIN_SECRET_LENGTH = 16


def main():
    parser = argparse.ArgumentParser(
        description="Create a signed scope.json for Attack Surface Mapper v3.4"
    )
    parser.add_argument(
        "-o", "--output",
        default="scope.json",
        help="Output path for the scope file (default: scope.json)",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target domains, IPs, or CIDRs. If omitted, uses the built-in example list.",
    )
    args = parser.parse_args()

    print("=== Recon Agent - Create Signed Scope (v3.4) ===\n")

    # Resolve target list
    if args.targets:
        raw_targets = args.targets
    else:
        # === EDIT THIS LIST if you prefer not to pass targets on the CLI ===
        raw_targets = [
            "example.com",
            "api.example.com",
            "test.example.com",
            "192.168.1.0/24",
        ]
        print(f"No targets provided on CLI — using built-in defaults ({len(raw_targets)} targets).")
        print("Tip: pass targets as arguments instead, e.g.:")
        print("  python3 create_scope.py example.com api.example.com 10.0.0.0/24\n")

    # Validate and canonicalize
    canonical: list[str] = []
    for t in raw_targets:
        try:
            canonical.append(canonicalize_target(t))
        except ValueError:
            print(f"❌ Invalid target: {t}")
            sys.exit(1)
    canonical = sorted(set(canonical))

    if not canonical:
        print("❌ No valid targets to sign.")
        sys.exit(1)

    print(f"Targets to authorize ({len(canonical)}):")
    for t in canonical:
        print(f"  • {t}")

    # Collect secret
    secret = input("\nEnter a strong secret key (keep this safe!): ").strip()
    if len(secret) < MIN_SECRET_LENGTH:
        print(f"❌ Secret must be at least {MIN_SECRET_LENGTH} characters.")
        sys.exit(1)

    # Sign
    signature = compute_signature(canonical, secret)

    scope_data = {
        "allowed_targets": canonical,
        "signature": signature,
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(scope_data, indent=2), encoding="utf-8")

    print(f"\n✅ {output_path} created successfully!")
    print(f"   Targets authorized: {len(canonical)}")
    print(f"   Signature: {signature[:16]}... (full signature saved in file)")
    print("\nKeep your secret key safe — you'll need it as RECON_SCOPE_SECRET when running the scanner.")


if __name__ == "__main__":
    main()
