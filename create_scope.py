#!/usr/bin/env python3
"""
Create a signed scope file (scope.json) for Attack Surface Mapper v3.4.0.

Targets are canonicalized (lowercased, stripped, deduplicated, sorted) before
signing so the HMAC matches regardless of how the operator formats them.
"""

import argparse
import getpass
import sys
from pathlib import Path

from scope_utils import (
    MIN_SECRET_LENGTH,
    compute_signature,
    parse_and_canonicalize_target,
    validate_secret,
)
import json


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Create a signed scope.json for Attack Surface Mapper v3.4.0"
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
    parser.add_argument(
        "--force", "-y",
        action="store_true",
        help="Overwrite existing scope file without prompting.",
    )
    args = parser.parse_args()

    print("=== Recon Agent - Create Signed Scope (v3.4.0) ===\n")

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
            canonical.append(parse_and_canonicalize_target(t))
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

    # Collect secret (not echoed to terminal)
    secret = getpass.getpass(f"\nEnter a strong secret key (min {MIN_SECRET_LENGTH} chars; input is hidden): ").strip()
    try:
        validate_secret(secret)
    except ValueError as e:
        print(f"❌ {e}")
        sys.exit(1)

    # Sign
    signature = compute_signature(canonical, secret)

    scope_data = {
        "allowed_targets": canonical,
        "signature": signature,
    }

    output_path = Path(args.output)
    if output_path.exists() and not args.force:
        answer = input(f"\n⚠  {output_path} already exists. Overwrite? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    output_path.write_text(json.dumps(scope_data, indent=2), encoding="utf-8")

    print(f"\n✅ {output_path} created successfully!")
    print(f"   Targets authorized: {len(canonical)}")
    print(f"   Signature: {signature[:16]}... (full signature saved in file)")
    print("\nKeep your secret key safe — you'll need it as RECON_SCOPE_SECRET when running the scanner.")


if __name__ == "__main__":
    main()
