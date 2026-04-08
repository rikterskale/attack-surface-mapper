#!/usr/bin/env python3
"""
Safe Standalone Recon Agent - Enterprise Edition (v3.4.0)

Signed-scope recon orchestrator that enforces HMAC-verified scope files
and runtime operator acknowledgement before executing third-party
discovery and scanning tools.
"""

import argparse
import asyncio
import atexit
import csv
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import structlog
from defusedxml.ElementTree import fromstring as safe_xml_fromstring
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from pydantic import BaseModel, Field

from scope_utils import (
    compute_signature,
    is_target_in_scope,
    parse_and_canonicalize_target,
    parse_targets_from_lines,
    update_and_resign,
    validate_secret,
    verify_signed_scope,
)

try:
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("attack-surface-mapper")
except Exception:
    __version__ = "3.4.0"  # fallback when running as uninstalled script

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

IS_WINDOWS = platform.system() == "Windows"
IS_KALI = bool(shutil.which("apt")) and "kali" in platform.platform().lower()

DEFAULT_WORDLIST = (
    "/usr/share/wordlists/dirb/common.txt" if IS_KALI
    else str(Path.home() / "wordlists" / "common.txt")
)

# ---------------------------------------------------------------------------
# Non-transient exceptions that should NOT trigger a retry
# ---------------------------------------------------------------------------

_NON_TRANSIENT_ERRORS: Tuple[type, ...] = (
    FileNotFoundError,
    PermissionError,
    NotADirectoryError,
    IsADirectoryError,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_LOG_FILE_HANDLE = None


def _configure_logger(log_path: Optional[Path] = None):
    """(Re)configure the global structlog pipeline.

    If *log_path* is provided, structured JSON logs are appended to that file.
    Otherwise logs go to the default print logger (stderr).

    The new factory is installed before the old file handle is closed so
    that concurrent log calls never hit a closed handle.
    """
    global _LOG_FILE_HANDLE
    old_handle = _LOG_FILE_HANDLE

    logger_factory = structlog.PrintLoggerFactory()
    if log_path:
        _LOG_FILE_HANDLE = open(log_path, "a", encoding="utf-8")
        logger_factory = structlog.WriteLoggerFactory(file=_LOG_FILE_HANDLE)
    else:
        _LOG_FILE_HANDLE = None

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=logger_factory,
    )

    # Close the previous handle *after* structlog is reconfigured.
    if old_handle:
        try:
            old_handle.close()
        except Exception:
            pass


def _cleanup_log_handle():
    """Close the log file handle on interpreter shutdown."""
    global _LOG_FILE_HANDLE
    if _LOG_FILE_HANDLE:
        try:
            _LOG_FILE_HANDLE.close()
        except Exception:
            pass
        _LOG_FILE_HANDLE = None


atexit.register(_cleanup_log_handle)

_configure_logger()
logger = structlog.get_logger("recon_agent")

# ---------------------------------------------------------------------------
# Tracing — spans are written to a file (not stdout) once main() sets up
# the output directory.  At module level we only create the provider.
# ---------------------------------------------------------------------------

trace.set_tracer_provider(TracerProvider())
_tracer_provider = trace.get_tracer_provider()
tracer = trace.get_tracer(__name__)

# Span file handle — registered with atexit for clean shutdown (fix #9).
_SPAN_FILE_HANDLE = None
_SPAN_EXPORTER_CONFIGURED = False


def _cleanup_span_handle():
    """Close the span file handle on interpreter shutdown."""
    global _SPAN_FILE_HANDLE
    try:
        _tracer_provider.shutdown()
    except Exception:
        pass
    if _SPAN_FILE_HANDLE:
        try:
            _SPAN_FILE_HANDLE.close()
        except Exception:
            pass
        _SPAN_FILE_HANDLE = None


atexit.register(_cleanup_span_handle)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single finding produced by a recon tool."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool: str
    asset: str
    indicator: str
    value: str
    type: str
    severity: str = "info"
    confidence: float = 0.5
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source_raw: Optional[str] = None
    correlated_to: List[str] = Field(default_factory=list)


class RunState(str, Enum):
    """Lifecycle states for a recon run."""

    QUEUED = "queued"
    RUNNING = "running"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass
class RunStateMachine:
    """Simple linear state machine with an audit trail of transitions."""

    state: RunState = RunState.QUEUED
    transitions: List[Tuple[str, str, float]] = field(default_factory=list)

    def transition(self, new_state: RunState):
        old = self.state
        self.state = new_state
        ts = time.time()
        self.transitions.append((old.value, new_state.value, ts))
        logger.info("state_transition", old_state=old.value, new_state=new_state.value)


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Determines which tools are allowed at each scan depth.

    Loads the authoritative mapping from ``external_tools.json`` next to this
    script.  Falls back to a built-in copy if the file is missing.  A custom
    policy JSON can overlay additional settings.
    """

    _BUILTIN_TOOLS: Dict[str, List[str]] = {
        "passive": ["amass", "subfinder", "assetfinder", "knockpy", "theharvester", "sherlock"],
        "standard": ["nmap", "rustscan", "naabu", "whatweb", "httpx", "httprobe"],
        "deep": ["nuclei", "nikto", "gobuster", "feroxbuster", "dirsearch"],
    }

    def __init__(self, policy_path: Optional[str] = None):
        tools_map = self._load_external_tools_json()
        self.policy: Dict = {
            "allowed_tools": tools_map,
            "environment": "production",
            "asset_classes": {"public": True, "internal": False},
        }
        if policy_path and Path(policy_path).exists():
            try:
                with open(policy_path, encoding="utf-8") as f:
                    self.policy.update(json.load(f))
                logger.info("policy_loaded", path=policy_path)
            except Exception as e:
                logger.error("policy_load_failed", error=str(e))
                raise ValueError(
                    f"Failed to load policy file '{policy_path}': {e}"
                ) from e

    @classmethod
    def _load_external_tools_json(cls) -> Dict[str, List[str]]:
        """Load tool-to-depth mapping from external_tools.json next to this script."""
        tools_file = Path(__file__).resolve().parent / "external_tools.json"
        if tools_file.exists():
            try:
                data = json.loads(tools_file.read_text(encoding="utf-8"))
                if (
                    isinstance(data, dict)
                    and all(isinstance(v, list) for v in data.values())
                    and all(
                        isinstance(item, str)
                        for v in data.values()
                        for item in v
                    )
                ):
                    logger.info("external_tools_loaded", path=str(tools_file))
                    return data
                logger.warning("external_tools_invalid_schema", path=str(tools_file))
            except Exception as e:
                logger.warning("external_tools_load_failed", error=str(e))
        return dict(cls._BUILTIN_TOOLS)

    def is_tool_allowed(self, tool: str, depth: str) -> bool:
        return tool in self.policy["allowed_tools"].get(depth, [])


# ---------------------------------------------------------------------------
# Scope validation (delegates to scope_utils)
# ---------------------------------------------------------------------------


class ScopeValidator:
    """Manages HMAC-signed scope files and runtime acknowledgement.

    All cryptographic and canonicalization logic lives in ``scope_utils``.
    This class provides the interface used by the rest of the scanner.
    """

    _compute_signature = staticmethod(compute_signature)

    @staticmethod
    def verify_signed_scope(scope_file: str, secret: str) -> List[str]:
        """Verify the HMAC signature of *scope_file* and return allowed targets."""
        targets = verify_signed_scope(scope_file, secret)
        logger.info("scope_verified", targets_count=len(targets))
        return targets

    @staticmethod
    def update_and_resign(scope_file: str, new_targets: List[str], secret: str):
        """Merge *new_targets* into the scope file, canonicalize, and re-sign."""
        logger.info("scope_update_starting", scope_file=scope_file, new_targets_provided=len(new_targets))
        try:
            update_and_resign(scope_file, new_targets, secret)
            logger.info("scope_update_success", scope_file=scope_file)
        except Exception as e:
            logger.exception(
                "scope_update_failed",
                scope_file=scope_file,
                error_type=type(e).__name__,
                error=str(e),
            )
            raise

    @staticmethod
    def runtime_acknowledgement():
        """Prompt the operator for explicit scan authorization."""
        ack = "I ACKNOWLEDGE THIS SCAN IS AUTHORIZED AND WITHIN SCOPE"
        print("\n" + "!" * 80)
        print("EXPLICIT AUTHORIZATION REQUIRED")
        print("!" * 80)
        print(f"Type exactly: {ack}")
        if input("\u2192 ").strip() != ack:
            raise PermissionError("Runtime acknowledgement failed - scan aborted")
        logger.info("runtime_acknowledgement_passed")


# ---------------------------------------------------------------------------
# Target helpers
# ---------------------------------------------------------------------------


def sanitize_filename_fragment(value: str) -> str:
    """Produce a filesystem-safe fragment from an arbitrary string."""
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", value.strip())
    return sanitized or "unknown_target"


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------


class CorrelationEngine:
    """Collects findings, deduplicates, and cross-references by asset."""

    def __init__(self):
        self.findings: List[Finding] = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def deduplicate(self) -> List[Finding]:
        """Remove findings with the same (tool, asset, indicator, severity)."""
        seen: set[tuple] = set()
        unique: List[Finding] = []
        for f in self.findings:
            key = (f.tool, f.asset, f.indicator, f.severity)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @staticmethod
    def correlate(findings: List[Finding]) -> List[Finding]:
        """Populate ``correlated_to`` for vulnerability-type findings."""
        asset_map: Dict[str, List[str]] = {}
        for f in findings:
            asset_map.setdefault(f.asset, []).append(f.id)

        for f in findings:
            if f.type == "vulnerability":
                f.correlated_to = [fid for fid in asset_map.get(f.asset, []) if fid != f.id]
        return findings


# ---------------------------------------------------------------------------
# Tool abstraction
# ---------------------------------------------------------------------------


class Tool:
    """Wraps an external recon binary with async execution and output parsing."""

    # Per-tool default confidence — structured parsers get higher confidence
    # than generic line parsers because findings are validated/typed.
    _CONFIDENCE: Dict[str, float] = {
        "nuclei": 0.9,
        "nmap": 0.9,
        "subfinder": 0.85,
        "httpx": 0.85,
        "naabu": 0.85,
        "nikto": 0.8,
        "whatweb": 0.75,
    }
    _DEFAULT_CONFIDENCE: float = 0.5

    def __init__(
        self,
        name: str,
        cmd_template: List[str],
        timeout: int = 180,
        stdin_target: bool = False,
        supports_cidr: bool = False,
    ):
        self.name = name
        self.cmd_template = cmd_template
        self.timeout = timeout
        self.stdin_target = stdin_target
        self.supports_cidr = supports_cidr
        self.extra_flags: List[str] = []

    def is_installed(self) -> bool:
        """Check whether the underlying binary is on ``$PATH``."""
        executable = self.cmd_template[0] if self.cmd_template else self.name
        return shutil.which(executable) is not None

    def _build_command(self, target: str) -> List[str]:
        command = [part.format(target=target, wordlist=DEFAULT_WORDLIST) for part in self.cmd_template]
        return command + self.extra_flags

    async def execute(
        self,
        target: str,
        semaphore: asyncio.Semaphore,
        output_dir: Path,
        retries: int = 2,
    ) -> List[Finding]:
        """Run the tool against *target* and return parsed findings.

        Logs a warning when the tool binary is not installed rather than
        silently returning an empty list.
        """
        if not self.is_installed():
            logger.warning(
                "tool_not_installed",
                tool=self.name,
                message=f"{self.name} is not installed -- skipping. Install it or use --auto-install on Kali.",
            )
            return []

        # Skip tools that don't understand CIDR when given a network target.
        if "/" in target and not self.supports_cidr:
            try:
                import ipaddress as _ipa
                _ipa.ip_network(target, strict=False)
                logger.warning(
                    "tool_skipped_cidr",
                    tool=self.name,
                    target=target,
                    message=f"{self.name} does not support CIDR targets -- skipping {target}.",
                )
                return []
            except ValueError:
                pass  # Not actually a CIDR — proceed normally

        async with semaphore:
            cmd = self._build_command(target)
            raw_target = sanitize_filename_fragment(target)
            raw_path = output_dir / f"raw_{raw_target}_{self.name}.txt"

            for attempt in range(retries + 1):
                with tracer.start_as_current_span(f"tool.{self.name}") as span:
                    span.set_attribute("tool", self.name)
                    span.set_attribute("target", target)
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdin=asyncio.subprocess.PIPE if self.stdin_target else None,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )

                        input_bytes = (target + "\n").encode("utf-8") if self.stdin_target else None
                        stdout, stderr = await asyncio.wait_for(proc.communicate(input=input_bytes), timeout=self.timeout)
                        output = stdout.decode(errors="ignore").strip()
                        err_output = stderr.decode(errors="ignore").strip()

                        raw_path.write_text(output, encoding="utf-8")

                        if proc.returncode not in (0, None) and not output:
                            raise RuntimeError(err_output or f"{self.name} exited with code {proc.returncode}")

                        if proc.returncode not in (0, None) and output:
                            logger.warning(
                                "tool_nonzero_exit_with_output",
                                tool=self.name,
                                target=target,
                                returncode=proc.returncode,
                                message="Tool exited non-zero but produced output -- parsing partial results.",
                            )

                        findings = self._parse_output(output, target)
                        logger.info("tool_complete", tool=self.name, target=target, findings=len(findings))
                        return findings

                    except _NON_TRANSIENT_ERRORS as e:
                        logger.error("tool_failed_non_transient", tool=self.name, target=target, error=str(e))
                        return []
                    except asyncio.TimeoutError:
                        if attempt == retries:
                            logger.error("tool_timeout", tool=self.name, target=target)
                            return []
                    except Exception as e:
                        if attempt == retries:
                            logger.error("tool_failed", tool=self.name, target=target, error=str(e))
                            return []
                        await asyncio.sleep(2 ** attempt)

            return []

    # ------------------------------------------------------------------
    # Output parsers
    # ------------------------------------------------------------------

    def _parse_output(self, output: str, target: str) -> List[Finding]:
        if not output.strip():
            return []

        parsers = {
            "subfinder": self._parse_json_lines,
            "httpx": self._parse_json_lines,
            "naabu": self._parse_json_lines,
            "nuclei": self._parse_json_lines,
            "nmap": self._parse_nmap_xml,
        }
        parser = parsers.get(self.name, self._parse_generic_lines)
        return parser(output, target)

    def _parse_generic_lines(self, output: str, target: str) -> List[Finding]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        conf = self._CONFIDENCE.get(self.name, self._DEFAULT_CONFIDENCE)
        return [
            Finding(
                tool=self.name,
                asset=target,
                indicator=line[:100],
                value=line,
                type="generic",
                severity="info",
                confidence=conf,
                source_raw=line,
            )
            for line in lines
        ]

    def _parse_json_lines(self, output: str, target: str) -> List[Finding]:
        findings: List[Finding] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if self.name == "nuclei":
                matched_at = obj.get("matched-at") or obj.get("host") or target
                info = obj.get("info", {})
                severity = str(info.get("severity", "info")).lower()
                finding_type = "vulnerability"
                indicator = obj.get("template-id") or obj.get("matcher-name") or "nuclei_finding"
                value = json.dumps(obj, ensure_ascii=False)
            elif self.name == "subfinder":
                matched_at = obj.get("host") or obj.get("input") or target
                severity = "info"
                finding_type = "subdomain"
                indicator = "subdomain"
                value = matched_at
            elif self.name == "httpx":
                matched_at = obj.get("url") or obj.get("host") or target
                severity = "info"
                finding_type = "web_service"
                indicator = f"http_{obj.get('status-code', 'unknown')}"
                value = json.dumps(obj, ensure_ascii=False)
            else:  # naabu
                host = obj.get("host") or target
                port = obj.get("port")
                matched_at = host
                severity = "info"
                finding_type = "open_port"
                indicator = f"port_{port}" if port is not None else "open_port"
                value = json.dumps(obj, ensure_ascii=False)

            findings.append(
                Finding(
                    tool=self.name,
                    asset=str(matched_at),
                    indicator=str(indicator),
                    value=str(value),
                    type=finding_type,
                    severity=severity,
                    confidence=self._CONFIDENCE.get(self.name, self._DEFAULT_CONFIDENCE),
                    source_raw=line,
                )
            )
        return findings

    def _parse_nmap_xml(self, output: str, target: str) -> List[Finding]:
        """Parse nmap XML output using defusedxml (required dependency)."""
        findings: List[Finding] = []
        try:
            root = safe_xml_fromstring(output)
        except Exception:
            return self._parse_generic_lines(output, target)

        for host in root.findall("host"):
            addr_elem = host.find("address")
            host_addr = addr_elem.get("addr") if addr_elem is not None else target
            for port in host.findall("./ports/port"):
                state_elem = port.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                port_id = port.get("portid", "unknown")
                proto = port.get("protocol", "tcp")
                svc_elem = port.find("service")
                svc_name = svc_elem.get("name") if svc_elem is not None else "unknown"
                raw = f"open {proto}/{port_id} service={svc_name}"
                findings.append(
                    Finding(
                        tool=self.name,
                        asset=str(host_addr),
                        indicator=f"open_{proto}_{port_id}",
                        value=raw,
                        type="open_port",
                        severity="info",
                        confidence=self._CONFIDENCE.get(self.name, self._DEFAULT_CONFIDENCE),
                        source_raw=raw,
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


class ToolRegistry:
    """Creates and manages all known recon tools, filtered by policy."""

    def __init__(self, policy: PolicyEngine):
        self.tools: Dict[str, Tool] = {}
        self.policy = policy
        self.package_map: Dict[str, str] = {
            "amass": "amass",
            "subfinder": "subfinder",
            "assetfinder": "assetfinder",
            "knockpy": "knockpy",
            "theharvester": "theharvester",
            "sherlock": "sherlock",
            "nmap": "nmap",
            "rustscan": "rustscan",
            "naabu": "naabu",
            "whatweb": "whatweb",
            "httpx": "httpx-toolkit",
            "httprobe": "httprobe",
            "nuclei": "nuclei",
            "nikto": "nikto",
            "gobuster": "gobuster",
            "feroxbuster": "feroxbuster",
            "dirsearch": "dirsearch",
        }

        # -- passive --
        self.register("amass", ["amass", "enum", "-d", "{target}", "-o", "/dev/stdout", "-silent"])
        self.register("subfinder", ["subfinder", "-d", "{target}", "-silent", "-json"])
        self.register("assetfinder", ["assetfinder", "--subs-only", "{target}"])
        self.register("knockpy", ["knockpy", "{target}", "--no-color"])
        self.register("theharvester", ["theHarvester", "-d", "{target}", "-b", "all", "-l", "500"])
        self.register("sherlock", ["sherlock", "{target}", "--timeout", "10", "--print-found"])

        # -- standard --
        self.register("nmap", ["nmap", "-T4", "-F", "--open", "-oX", "-", "{target}"], supports_cidr=True)
        self.register("rustscan", ["rustscan", "-a", "{target}", "--ulimit", "5000", "--", "-sV"], supports_cidr=True)
        self.register("naabu", ["naabu", "-host", "{target}", "-silent", "-json"], supports_cidr=True)
        self.register("whatweb", ["whatweb", "--color=never", "--aggression=3", "{target}"])
        self.register("httpx", ["httpx", "-silent", "-json", "-status-code", "-title", "-tech-detect"], stdin_target=True)
        self.register("httprobe", ["httprobe", "-c", "50"], stdin_target=True)

        # -- deep --
        self.register("nuclei", ["nuclei", "-silent", "-jsonl", "-severity", "critical,high"], stdin_target=True)
        self.register("nikto", ["nikto", "-h", "{target}", "-Format", "json", "-output", "/dev/stdout"])
        self.register("gobuster", ["gobuster", "dir", "-u", "{target}", "-w", "{wordlist}", "-q", "-k", "--no-error"])
        self.register("feroxbuster", ["feroxbuster", "-u", "{target}", "-w", "{wordlist}", "-q", "--no-state"])
        self.register("dirsearch", ["dirsearch", "-u", "{target}", "-w", "{wordlist}", "-q", "-e", "php,asp,aspx,txt,html"])

    def register(self, name: str, cmd_template: List[str], stdin_target: bool = False, supports_cidr: bool = False):
        self.tools[name] = Tool(name, cmd_template, stdin_target=stdin_target, supports_cidr=supports_cidr)

    def get_allowed_tools(self, depth: str) -> List[str]:
        return [t for t in self.tools if self.policy.is_tool_allowed(t, depth)]

    def get_missing_tools(self, depth: str) -> List[str]:
        return [t for t in self.get_allowed_tools(depth) if not self.tools[t].is_installed()]

    def auto_install_missing(self, depth: str) -> List[str]:
        """Attempt to ``apt install`` missing tools on Kali Linux."""
        missing = self.get_missing_tools(depth)
        if not missing:
            return []
        if not IS_KALI:
            logger.warning("auto_install_unsupported_platform", platform=platform.platform(), missing=missing)
            return missing

        apt = shutil.which("apt-get") or shutil.which("apt")
        if not apt:
            logger.warning("auto_install_missing_package_manager", missing=missing)
            return missing

        packages = sorted({self.package_map.get(tool, tool) for tool in missing})
        cmd = [apt, "install", "-y", *packages]
        if hasattr(os, "getuid") and os.getuid() != 0:
            sudo = shutil.which("sudo")
            if not sudo:
                logger.warning("auto_install_needs_root", missing=missing)
                return missing
            cmd = [sudo] + cmd
        try:
            logger.info("auto_install_start", packages=packages, command=" ".join(cmd))
            subprocess.run(cmd, check=True)
        except Exception as e:
            logger.error("auto_install_failed", error=str(e), packages=packages)
            return self.get_missing_tools(depth)
        return self.get_missing_tools(depth)


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------


class SQLiteDB:
    """Thin wrapper around a SQLite database for storing findings."""

    def __init__(self, db_path: Path):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                tool TEXT, asset TEXT, indicator TEXT, value TEXT,
                type TEXT, severity TEXT, confidence REAL,
                timestamp TEXT, source_raw TEXT, correlated_to TEXT
            )
            """
        )
        self.conn.commit()

    def add_finding(self, finding_dict: Dict):
        """Insert a single finding.  Caller should use :meth:`commit` to batch."""
        self.conn.execute(
            """
            INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_dict["id"],
                finding_dict["tool"],
                finding_dict["asset"],
                finding_dict["indicator"],
                finding_dict["value"],
                finding_dict["type"],
                finding_dict["severity"],
                finding_dict["confidence"],
                finding_dict["timestamp"],
                finding_dict.get("source_raw"),
                json.dumps(finding_dict.get("correlated_to", [])),
            ),
        )

    def commit(self):
        """Explicitly commit the current transaction."""
        self.conn.commit()

    def close(self):
        self.conn.close()


# ---------------------------------------------------------------------------
# Recon runner
# ---------------------------------------------------------------------------


class ReconAgentRun:
    """Orchestrates a single recon run across all targets and tools."""

    def __init__(
        self,
        registry: ToolRegistry,
        db: SQLiteDB,
        semaphore: asyncio.Semaphore,
        output_dir: Path,
        retries: int,
        state_machine: RunStateMachine,
    ):
        self.registry = registry
        self.db = db
        self.semaphore = semaphore
        self.output_dir = output_dir
        self.retries = max(0, retries)
        self.state = state_machine
        self.correlator = CorrelationEngine()

    async def run_recon(self, targets: List[str], depth: str) -> Dict:
        self.state.transition(RunState.RUNNING)
        start = time.time()
        errors = []

        with tracer.start_as_current_span("recon.run") as span:
            span.set_attribute("depth", depth)
            span.set_attribute("targets_count", len(targets))

            for target in targets:
                target_dir = self.output_dir / sanitize_filename_fragment(target)
                target_dir.mkdir(parents=True, exist_ok=True)

                try:
                    tools = self.registry.get_allowed_tools(depth)
                    tasks = [self.registry.tools[t].execute(target, self.semaphore, target_dir, self.retries) for t in tools]
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    for res in results:
                        if isinstance(res, Exception):
                            errors.append(f"{target}: {type(res).__name__}: {res}")
                        elif isinstance(res, list):
                            for f in res:
                                self.correlator.add_finding(f)
                except Exception as e:
                    errors.append(str(e))

        unique = self.correlator.deduplicate()
        correlated = CorrelationEngine.correlate(unique)

        # Batch-insert all findings in a single transaction.
        for finding in correlated:
            self.db.add_finding(finding.model_dump())
        self.db.commit()

        final_state = RunState.COMPLETED if not errors else RunState.PARTIAL_SUCCESS
        self.state.transition(final_state)

        return {
            "run_id": str(uuid.uuid4()),
            "targets": targets,
            "depth": depth,
            "state": final_state.value,
            "findings_count": len(correlated),
            "duration_seconds": round(time.time() - start, 1),
            "errors": errors,
            "output_dir": str(self.output_dir),
        }


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------


def export_results(db: SQLiteDB, output_dir: Path):
    """Write findings from SQLite to JSONL and CSV files."""
    cursor = db.conn.execute("SELECT * FROM findings")
    findings = cursor.fetchall()
    cols = [desc[0] for desc in cursor.description]

    with open(output_dir / "findings.jsonl", "w", encoding="utf-8") as f:
        for row in findings:
            f.write(json.dumps(dict(zip(cols, row))) + "\n")

    with open(output_dir / "findings.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        writer.writerows(findings)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args():
    parser = argparse.ArgumentParser(
        description=f"Enterprise Recon Agent v{__version__}"
    )
    parser.add_argument("target", nargs="?", help="Single target")
    parser.add_argument("--file", "-f", help="Targets file")
    parser.add_argument("--depth", choices=["passive", "standard", "deep"], default="standard")
    parser.add_argument("--output-dir", "-o", default="./recon_results")
    parser.add_argument("--threads", "-t", type=int, default=8)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--scope-file", required=True, help="Signed scope.json")
    parser.add_argument("--scope-secret", help="Secret (prefer RECON_SCOPE_SECRET env var)")
    parser.add_argument("--update-scope", action="store_true", help="Auto-merge targets file into scope.json and re-sign")
    parser.add_argument("--policy", help="Policy JSON file")
    parser.add_argument("--auto-install", action="store_true", help="Attempt apt-based install of missing tools on Kali Linux")
    parser.add_argument("--dry-run", action="store_true", help="Show what would run without executing any tools")
    parser.add_argument(
        "--no-ack", action="store_true",
        help="Skip interactive acknowledgement prompt (requires RECON_UNATTENDED=1 env var as safety gate)",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    if args.threads < 1:
        parser.error("--threads must be >= 1")
    return args


async def main():
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    _configure_logger(output_dir / "recon.log")
    global logger
    logger = structlog.get_logger("recon_agent")

    logger.info("recon_started", version=__version__, depth=args.depth)

    if args.scope_secret:
        logger.warning("scope_secret_cli_used", message="Prefer RECON_SCOPE_SECRET env var over --scope-secret")

    secret = args.scope_secret or os.getenv("RECON_SCOPE_SECRET")
    if not secret:
        logger.error("missing_scope_secret")
        print("\u274c Error: Scope secret is required (set RECON_SCOPE_SECRET; --scope-secret is supported but discouraged)")
        sys.exit(1)

    # Enforce minimum secret length (fix #5)
    try:
        validate_secret(secret)
    except ValueError as e:
        logger.error("scope_secret_too_short", error=str(e))
        print(f"\u274c Error: {e}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Read targets file once (reused for --update-scope and target list)
    # ------------------------------------------------------------------
    file_valid: List[str] = []
    file_invalid: List[str] = []

    if args.file:
        try:
            file_lines = Path(args.file).read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            logger.error("targets_file_not_found", file=args.file)
            print(f"\u274c Error: Targets file '{args.file}' not found.")
            sys.exit(1)

        file_valid, file_invalid = parse_targets_from_lines(file_lines)
        if file_invalid:
            logger.warning("invalid_targets_skipped", count=len(file_invalid), examples=file_invalid[:5])

    # ------------------------------------------------------------------
    # Optional: merge targets file into scope and re-sign
    # ------------------------------------------------------------------
    if args.update_scope and args.file:
        logger.info("scope_update_attempted", scope_file=args.scope_file, targets_file=args.file)
        try:
            if not file_valid:
                logger.error("no_valid_targets_in_file", targets_file=args.file)
                print("\u274c Error: No valid targets found in targets file")
                sys.exit(1)

            ScopeValidator.update_and_resign(args.scope_file, file_valid, secret)
        except FileNotFoundError:
            logger.error("targets_file_not_found", file=args.file)
            print(f"\u274c Error: Targets file '{args.file}' not found.")
            sys.exit(1)
        except PermissionError:
            logger.error("permission_denied_updating_scope", scope_file=args.scope_file)
            print(f"\u274c Error: Cannot write to '{args.scope_file}' (permission denied).")
            sys.exit(1)
        except ValueError as e:
            logger.error("scope_update_value_error", error=str(e))
            print(f"\u274c Scope update failed: {e}")
            sys.exit(1)
        except Exception:
            logger.exception("unexpected_scope_update_error", scope_file=args.scope_file, targets_file=args.file)
            print("\u274c Unexpected error while updating scope.")
            if args.verbose:
                import traceback

                traceback.print_exc()
            sys.exit(1)

    # ------------------------------------------------------------------
    # Gate 1: Verify signed scope FIRST
    # ------------------------------------------------------------------
    try:
        allowed_targets = ScopeValidator.verify_signed_scope(args.scope_file, secret)
    except FileNotFoundError:
        logger.error("scope_file_not_found", scope_file=args.scope_file)
        print(f"\u274c Error: Scope file '{args.scope_file}' not found.")
        sys.exit(1)
    except ValueError as e:
        logger.error("scope_verification_failed", error=str(e))
        print(f"\u274c Error: {e}")
        sys.exit(1)
    except Exception:
        logger.exception("unexpected_scope_verification_error", scope_file=args.scope_file)
        print("\u274c Unexpected error while verifying scope file.")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    canonical_allowed = set()
    for allowed in allowed_targets:
        try:
            canonical_allowed.add(parse_and_canonicalize_target(allowed))
        except ValueError:
            logger.warning("invalid_allowed_target_in_scope", target=allowed)

    # ------------------------------------------------------------------
    # Collect and filter targets (uses CIDR-aware matching)
    # ------------------------------------------------------------------
    targets: List[str] = []
    if args.target:
        try:
            targets.append(parse_and_canonicalize_target(args.target))
        except ValueError as e:
            logger.error("invalid_cli_target", target=args.target, error=str(e))
            print(f"\u274c Error: Invalid target '{args.target}': {e}")
            sys.exit(1)
    if args.file:
        targets.extend(file_valid)

    targets = [t for t in targets if is_target_in_scope(t, canonical_allowed)]
    if not targets:
        logger.error("no_valid_targets_in_scope")
        print("\u274c Error: No provided targets are authorized by the signed scope.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Build pipeline
    # ------------------------------------------------------------------
    policy = PolicyEngine(args.policy)
    registry = ToolRegistry(policy)

    # ------------------------------------------------------------------
    # Dry-run: show what would execute, then exit — BEFORE acknowledgement
    # so operators can preview without typing the full ack string.
    # ------------------------------------------------------------------
    if args.dry_run:
        allowed_tools = registry.get_allowed_tools(args.depth)
        missing = registry.get_missing_tools(args.depth)
        installed = [t for t in allowed_tools if t not in missing]

        print("\n" + "=" * 80)
        print("DRY RUN — no tools will be executed")
        print("=" * 80)
        print(f"\nDepth:   {args.depth}")
        print(f"Targets: ({len(targets)})")
        for t in targets:
            print(f"  • {t}")
        print(f"\nTools allowed at '{args.depth}' depth: ({len(allowed_tools)})")
        for t in allowed_tools:
            status = "✅ installed" if t in installed else "❌ MISSING"
            print(f"  • {t:20s} {status}")
        print(f"\nTotal executions: {len(targets)} targets × {len(installed)} installed tools = {len(targets) * len(installed)}")
        if missing:
            print(f"\n⚠  {len(missing)} tools missing: {', '.join(missing)}")
            print("   Install them or use --auto-install on Kali.")
        print()
        return 0

    # ------------------------------------------------------------------
    # Gate 2: Runtime operator acknowledgement (after scope is verified,
    # but skipped for --dry-run above and --no-ack in CI/automated mode)
    # ------------------------------------------------------------------
    if args.no_ack:
        if os.getenv("RECON_UNATTENDED") != "1":
            logger.error("no_ack_requires_env_var")
            print("\u274c Error: --no-ack requires RECON_UNATTENDED=1 environment variable as a safety gate.")
            sys.exit(1)
        logger.info("runtime_acknowledgement_skipped", reason="--no-ack with RECON_UNATTENDED=1")
    else:
        ScopeValidator.runtime_acknowledgement()

    if args.auto_install:
        remaining_missing = registry.auto_install_missing(args.depth)
        if remaining_missing:
            logger.warning("tools_still_missing_after_auto_install", tools=remaining_missing)

    missing_tools = registry.get_missing_tools(args.depth)
    if missing_tools:
        logger.warning("missing_tools", depth=args.depth, tools=missing_tools)

    # Write span traces to a file instead of stdout (only for non-dry-run paths).
    global _SPAN_FILE_HANDLE, _SPAN_EXPORTER_CONFIGURED
    try:
        span_log_path = output_dir / "spans.jsonl"
        _SPAN_FILE_HANDLE = open(span_log_path, "a", encoding="utf-8")

        class _FileSpanExporter(ConsoleSpanExporter):
            def __init__(self, fh):
                super().__init__(out=fh)

        if not _SPAN_EXPORTER_CONFIGURED:
            _tracer_provider.add_span_processor(
                BatchSpanProcessor(_FileSpanExporter(_SPAN_FILE_HANDLE))
            )
            _SPAN_EXPORTER_CONFIGURED = True
    except Exception as e:
        logger.warning("span_exporter_setup_failed", error=str(e))

    db = SQLiteDB(output_dir / "findings.db")
    try:
        semaphore = asyncio.Semaphore(args.threads)
        state_machine = RunStateMachine()

        agent = ReconAgentRun(registry, db, semaphore, output_dir, args.retries, state_machine)
        result = await agent.run_recon(targets, args.depth)

        export_results(db, output_dir)
    finally:
        db.close()
        _cleanup_span_handle()
        _cleanup_span_handle()
        _cleanup_span_handle()
        _cleanup_span_handle()

    logger.info("recon_completed", **result)
    print("\n" + "=" * 80)
    print("RECON AGENT COMPLETE")
    print("=" * 80)
    print(json.dumps(result, indent=2))
    return 0


def cli():
    """Synchronous entry point used by ``[project.scripts]``."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("scan_cancelled_by_user")
        sys.exit(130)
    except Exception as e:
        logger.critical("fatal_error", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    cli()
