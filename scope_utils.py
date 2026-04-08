"""
Shared scope utilities for Attack Surface Mapper v3.4.

Canonical target parsing, HMAC signing, and scope validation live here
so that every entry point (scanner, create_scope.py, one-liners, docs)
uses identical logic.
"""

import hashlib
import hmac
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Target validation & canonicalization
# ---------------------------------------------------------------------------

_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
)


def parse_and_canonicalize_target(target: str) -> str:
    """Normalize a user-supplied target string to a canonical lowercase form.

    Strips schemes, ports, and URL paths.  Preserves CIDR notation
    (e.g. ``192.168.1.0/24``) so that network ranges are correctly
    represented in scope files and signature payloads.

    Validates the result as one of: IPv4/IPv6 address, IPv4/IPv6 network
    (CIDR), or a domain name matching RFC 1123.
    """
    target = target.strip().lower()

    # Strip scheme
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    target = target.rstrip("/")

    # Separate CIDR suffix from URL path:
    # If the part after the first "/" is a small integer, treat it as CIDR.
    if "/" in target:
        head, tail = target.split("/", 1)
        if tail.isdigit() and 0 <= int(tail) <= 128:
            # Likely CIDR notation — preserve it
            target = f"{head}/{tail}"
        else:
            # URL path — discard
            target = head

    # Strip port — but only when there is exactly one colon (host:port).
    # Multiple colons indicate a bare IPv6 address (e.g. 2001:db8::80)
    # which must not have its last segment mistaken for a port.
    # Bracketed IPv6 like [::1]:8080 is handled by urlparse above.
    if target.count(":") == 1:
        host, port = target.rsplit(":", 1)
        if port.isdigit():
            target = host

    # Validate as IP address
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Validate as IP network (CIDR)
    try:
        ipaddress.ip_network(target, strict=False)
        return str(ipaddress.ip_network(target, strict=False))
    except ValueError:
        pass

    # Validate as domain
    if _DOMAIN_REGEX.match(target):
        return target

    raise ValueError(f"Invalid target format: {target}")


def canonicalize_targets(targets: List[str]) -> List[str]:
    """Return a sorted, deduplicated, canonicalized copy of *targets*.

    Invalid entries are silently dropped.  Callers that need diagnostics
    should use :func:`parse_targets_from_lines` instead.
    """
    canonical: List[str] = []
    for t in targets:
        try:
            canonical.append(parse_and_canonicalize_target(t))
        except ValueError:
            pass
    return sorted(set(canonical))


def parse_targets_from_lines(lines: List[str]) -> Tuple[List[str], List[str]]:
    """Split raw text lines into (valid_targets, invalid_targets)."""
    valid_targets: List[str] = []
    invalid_targets: List[str] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            valid_targets.append(parse_and_canonicalize_target(line))
        except ValueError:
            invalid_targets.append(line.strip())
    return valid_targets, invalid_targets


def is_target_in_scope(target: str, allowed_targets: set) -> bool:
    """Check whether *target* is authorized by *allowed_targets*.

    Performs exact string matching first, then checks whether *target*
    is an IP address that falls within any CIDR network entry in the
    allowed set.  This allows a scope entry like ``10.0.0.0/24`` to
    authorize individual IPs such as ``10.0.0.1``.
    """
    if target in allowed_targets:
        return True

    # Check if target is an IP that falls within a CIDR scope entry
    try:
        target_addr = ipaddress.ip_address(target)
    except ValueError:
        return False  # Not an IP — only exact match applies

    for allowed in allowed_targets:
        try:
            network = ipaddress.ip_network(allowed, strict=False)
            if target_addr in network:
                return True
        except ValueError:
            continue  # Not a network entry — skip
    return False


# ---------------------------------------------------------------------------
# HMAC signing
# ---------------------------------------------------------------------------

MIN_SECRET_LENGTH = 16


def compute_signature(targets: List[str], secret: str) -> str:
    """Compute HMAC-SHA256 over canonicalized, sorted targets."""
    canonical = canonicalize_targets(targets)
    payload = json.dumps({"allowed_targets": canonical}, sort_keys=True).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def validate_secret(secret: str) -> None:
    """Raise ValueError if the secret does not meet minimum requirements."""
    if not secret or len(secret) < MIN_SECRET_LENGTH:
        raise ValueError(
            f"Secret must be at least {MIN_SECRET_LENGTH} characters "
            f"(got {len(secret) if secret else 0})."
        )


# ---------------------------------------------------------------------------
# Scope file operations
# ---------------------------------------------------------------------------


def validate_scope_schema(data: Dict[str, Any]) -> List[str]:
    """Validate the shape of a scope dict and return the target list."""
    targets = data.get("allowed_targets")
    signature = data.get("signature")

    if not isinstance(targets, list):
        raise ValueError("Scope file must contain 'allowed_targets' as a list")
    if not all(isinstance(t, str) for t in targets):
        raise ValueError("All entries in 'allowed_targets' must be strings")
    if not isinstance(signature, str) or not signature.strip():
        raise ValueError("Scope file missing signature")
    return targets


def verify_signed_scope(scope_file: str, secret: str) -> List[str]:
    """Verify the HMAC signature of *scope_file* and return allowed targets.

    Targets are canonicalized before signature comparison so that case
    differences between the file and the running scan do not cause
    silent mismatches.
    """
    path = Path(scope_file)
    if not path.exists():
        raise FileNotFoundError(f"Scope file {scope_file} not found")
    # Enforce the same secret policy used by CLI entry points.
    validate_secret(secret)

    data = json.loads(path.read_text(encoding="utf-8"))
    targets = validate_scope_schema(data)
    signature = data["signature"]

    expected = compute_signature(targets, secret)

    if not hmac.compare_digest(expected, signature):
        raise ValueError("Invalid scope signature - authorization denied")

    return canonicalize_targets(targets)


def update_and_resign(scope_file: str, new_targets: List[str], secret: str) -> None:
    """Merge *new_targets* into the scope file, canonicalize, and re-sign."""
    path = Path(scope_file)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        existing = set(validate_scope_schema(data))
    else:
        existing = set()

    merged = canonicalize_targets(list(existing) + new_targets)
    signature = compute_signature(merged, secret)

    updated = {"allowed_targets": merged, "signature": signature}
    path.write_text(json.dumps(updated, indent=2), encoding="utf-8")
