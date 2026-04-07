#!/usr/bin/env python3
"""
Safe Standalone Recon Agent - Enterprise Edition (v3.3)
"""

import argparse
import asyncio
import csv
import hashlib
import hmac
import ipaddress
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
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import structlog
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from pydantic import BaseModel, Field

IS_WINDOWS = platform.system() == "Windows"
IS_KALI = bool(shutil.which("apt")) and "kali" in platform.platform().lower()

DEFAULT_WORDLIST = (
    "/usr/share/wordlists/dirb/common.txt" if IS_KALI
    else str(Path.home() / "wordlists" / "common.txt")
)

_LOG_FILE_HANDLE = None


def _configure_logger(log_path: Path | None = None):
    global _LOG_FILE_HANDLE
    if _LOG_FILE_HANDLE:
        _LOG_FILE_HANDLE.close()
        _LOG_FILE_HANDLE = None

    logger_factory = structlog.PrintLoggerFactory()
    if log_path:
        _LOG_FILE_HANDLE = open(log_path, "a", encoding="utf-8")
        logger_factory = structlog.WriteLoggerFactory(file=_LOG_FILE_HANDLE)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=logger_factory,
    )


_configure_logger()
logger = structlog.get_logger("recon_agent")

trace.set_tracer_provider(TracerProvider())
tracer_provider = trace.get_tracer_provider()
tracer_provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
tracer = trace.get_tracer(__name__)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool: str
    asset: str
    indicator: str
    value: str
    type: str
    severity: str = "info"
    confidence: float = 0.8
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    source_raw: str | None = None
    correlated_to: List[str] = Field(default_factory=list)


from enum import Enum


class RunState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass
class RunStateMachine:
    state: RunState = RunState.QUEUED
    transitions: List[Tuple[str, str, float]] = field(default_factory=list)

    def transition(self, new_state: RunState):
        old = self.state
        self.state = new_state
        ts = time.time()
        self.transitions.append((old.value, new_state.value, ts))
        logger.info("state_transition", old_state=old.value, new_state=new_state.value)


class PolicyEngine:
    def __init__(self, policy_path: str | None = None):
        self.policy: Dict = {
            "allowed_tools": {
                "passive": ["amass", "subfinder", "assetfinder", "knockpy", "theharvester", "sherlock"],
                "standard": ["nmap", "rustscan", "naabu", "whatweb", "httpx", "httprobe"],
                "deep": ["nuclei", "nikto", "gobuster", "feroxbuster", "dirsearch"],
            },
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

    def is_tool_allowed(self, tool: str, depth: str) -> bool:
        return tool in self.policy["allowed_tools"].get(depth, [])


class ScopeValidator:
    @staticmethod
    def _validate_scope_schema(data: Dict[str, Any]) -> List[str]:
        targets = data.get("allowed_targets")
        signature = data.get("signature")

        if not isinstance(targets, list):
            raise ValueError("Scope file must contain 'allowed_targets' as a list")
        if not all(isinstance(t, str) for t in targets):
            raise ValueError("All entries in 'allowed_targets' must be strings")
        if not isinstance(signature, str) or not signature.strip():
            raise ValueError("Scope file missing signature")
        return targets

    @staticmethod
    def verify_signed_scope(scope_file: str, secret: str) -> List[str]:
        path = Path(scope_file)
        if not path.exists():
            raise FileNotFoundError(f"Scope file {scope_file} not found")

        data = json.loads(path.read_text(encoding="utf-8"))
        targets = ScopeValidator._validate_scope_schema(data)
        signature = data["signature"]

        payload = json.dumps({"allowed_targets": targets}, sort_keys=True).encode()
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected, signature):
            raise ValueError("Invalid scope signature - authorization denied")

        logger.info("scope_verified", targets_count=len(targets))
        return targets

    @staticmethod
    def update_and_resign(scope_file: str, new_targets: List[str], secret: str):
        logger.info("scope_update_starting", scope_file=scope_file, new_targets_provided=len(new_targets))

        path = Path(scope_file)
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                existing = set(ScopeValidator._validate_scope_schema(data))
            else:
                existing = set()

            merged = sorted(existing.union(set(new_targets)))
            payload = json.dumps({"allowed_targets": merged}, sort_keys=True).encode()
            signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

            updated = {"allowed_targets": merged, "signature": signature}
            path.write_text(json.dumps(updated, indent=2), encoding="utf-8")

            logger.info(
                "scope_update_success",
                new_targets_added=len(merged) - len(existing),
                total_targets=len(merged),
                scope_file=scope_file,
            )
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
        ack = "I ACKNOWLEDGE THIS SCAN IS AUTHORIZED AND WITHIN SCOPE"
        print("\n" + "!" * 80)
        print("EXPLICIT AUTHORIZATION REQUIRED")
        print("!" * 80)
        print(f"Type exactly: {ack}")
        if input("→ ").strip() != ack:
            raise PermissionError("Runtime acknowledgement failed - scan aborted")
        logger.info("runtime_acknowledgement_passed")


def parse_and_canonicalize_target(target: str) -> str:
    target = target.strip().lower()
    if "://" in target:
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

    domain_regex = r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
    if re.match(domain_regex, target):
        return target
    raise ValueError(f"Invalid target format: {target}")


def sanitize_filename_fragment(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", value.strip())
    return sanitized or "unknown_target"


class CorrelationEngine:
    def __init__(self):
        self.findings: List[Finding] = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def deduplicate(self) -> List[Finding]:
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
        asset_map: Dict[str, List[str]] = {}
        for f in findings:
            asset_map.setdefault(f.asset, []).append(f.id)

        for f in findings:
            if f.type == "vulnerability":
                f.correlated_to = [fid for fid in asset_map.get(f.asset, []) if fid != f.id]
        return findings


class Tool:
    def __init__(
        self,
        name: str,
        cmd_template: List[str],
        timeout: int = 180,
        stdin_target: bool = False,
    ):
        self.name = name
        self.cmd_template = cmd_template
        self.timeout = timeout
        self.stdin_target = stdin_target
        self.extra_flags: List[str] = []

    def is_installed(self) -> bool:
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
        if not self.is_installed():
            return []

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

                        findings = self._parse_output(output, target)
                        logger.info("tool_complete", tool=self.name, target=target, findings=len(findings))
                        return findings

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
        return [
            Finding(
                tool=self.name,
                asset=target,
                indicator=line[:100],
                value=line,
                type="generic",
                severity="info",
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
                    source_raw=line,
                )
            )
        return findings

    def _parse_nmap_xml(self, output: str, target: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
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
                findings.append(
                    Finding(
                        tool=self.name,
                        asset=str(host_addr),
                        indicator=f"open_{proto}_{port_id}",
                        value=f"open {proto}/{port_id} service={svc_name}",
                        type="open_port",
                        severity="info",
                    )
                )
        return findings


class ToolRegistry:
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

        self.register("amass", ["amass", "enum", "-d", "{target}", "-o", "/dev/stdout", "-silent"])
        self.register("subfinder", ["subfinder", "-d", "{target}", "-silent", "-json"])
        self.register("assetfinder", ["assetfinder", "--subs-only", "{target}"])
        self.register("knockpy", ["knockpy", "{target}", "--no-color"])

        self.register("theharvester", ["theHarvester", "-d", "{target}", "-b", "all", "-l", "500"])
        self.register("sherlock", ["sherlock", "{target}", "--timeout", "10", "--print-found"])

        self.register("nmap", ["nmap", "-T4", "-F", "--open", "-oX", "-", "{target}"])
        self.register("rustscan", ["rustscan", "-a", "{target}", "--ulimit", "5000", "--", "-sV"])
        self.register("naabu", ["naabu", "-host", "{target}", "-silent", "-json"])

        self.register("whatweb", ["whatweb", "--color=never", "--aggression=3", "{target}"])
        self.register("httpx", ["httpx", "-silent", "-json", "-status-code", "-title", "-tech-detect"], stdin_target=True)
        self.register("httprobe", ["httprobe", "-c", "50"], stdin_target=True)

        self.register("nuclei", ["nuclei", "-silent", "-jsonl", "-severity", "critical,high"], stdin_target=True)
        self.register("nikto", ["nikto", "-h", "{target}", "-Format", "json", "-output", "/dev/stdout"])

        self.register("gobuster", ["gobuster", "dir", "-u", "https://{target}", "-w", "{wordlist}", "-q", "-k", "--no-error"])
        self.register("feroxbuster", ["feroxbuster", "-u", "https://{target}", "-w", "{wordlist}", "-q", "--no-state"])
        self.register("dirsearch", ["dirsearch", "-u", "https://{target}", "-w", "{wordlist}", "-q", "-e", "php,asp,aspx,txt,html"])

    def register(self, name: str, cmd_template: List[str], stdin_target: bool = False):
        self.tools[name] = Tool(name, cmd_template, stdin_target=stdin_target)

    def get_allowed_tools(self, depth: str) -> List[str]:
        return [t for t in self.tools if self.policy.is_tool_allowed(t, depth)]

    def get_missing_tools(self, depth: str) -> List[str]:
        return [t for t in self.get_allowed_tools(depth) if not self.tools[t].is_installed()]

    def auto_install_missing(self, depth: str) -> List[str]:
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
        try:
            logger.info("auto_install_start", packages=packages, command=" ".join(cmd))
            subprocess.run(cmd, check=True)
        except Exception as e:
            logger.error("auto_install_failed", error=str(e), packages=packages)
            return self.get_missing_tools(depth)
        return self.get_missing_tools(depth)


class SQLiteDB:
    def __init__(self, db_path: Path):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                tool TEXT, asset TEXT, indicator TEXT, value TEXT,
                type TEXT, severity TEXT, confidence REAL,
                timestamp TEXT, correlated_to TEXT
            )
            """
        )
        self.conn.commit()

    def add_finding(self, finding_dict: Dict):
        self.conn.execute(
            """
            INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                json.dumps(finding_dict.get("correlated_to", [])),
            ),
        )
        self.conn.commit()

    def close(self):
        self.conn.close()


class ReconAgentRun:
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
        for finding in correlated:
            self.db.add_finding(finding.model_dump())

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


def export_results(db: SQLiteDB, output_dir: Path):
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


def parse_args():
    parser = argparse.ArgumentParser(description="Enterprise Recon Agent v3.3")
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
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser.parse_args()


async def main():
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    _configure_logger(output_dir / "recon.log")
    global logger
    logger = structlog.get_logger("recon_agent")

    logger.info("recon_started", version="3.3", depth=args.depth)

    if args.scope_secret:
        logger.warning("scope_secret_cli_used", message="Prefer RECON_SCOPE_SECRET env var over --scope-secret")

    secret = args.scope_secret or os.getenv("RECON_SCOPE_SECRET")
    if not secret:
        logger.error("missing_scope_secret")
        print("❌ Error: Scope secret is required (set RECON_SCOPE_SECRET; --scope-secret is supported but discouraged)")
        sys.exit(1)

    if args.update_scope and args.file:
        logger.info("scope_update_attempted", scope_file=args.scope_file, targets_file=args.file)
        try:
            raw_lines = Path(args.file).read_text(encoding="utf-8").splitlines()
            valid_targets: List[str] = []
            invalid_targets: List[str] = []

            for line in raw_lines:
                if line.strip():
                    try:
                        valid_targets.append(parse_and_canonicalize_target(line))
                    except ValueError:
                        invalid_targets.append(line.strip())

            if invalid_targets:
                logger.warning("invalid_targets_skipped", count=len(invalid_targets), examples=invalid_targets[:5])

            if not valid_targets:
                logger.error("no_valid_targets_in_file", targets_file=args.file)
                print("❌ Error: No valid targets found in targets file")
                sys.exit(1)

            ScopeValidator.update_and_resign(args.scope_file, valid_targets, secret)
        except FileNotFoundError:
            logger.error("targets_file_not_found", file=args.file)
            print(f"❌ Error: Targets file '{args.file}' not found.")
            sys.exit(1)
        except PermissionError:
            logger.error("permission_denied_updating_scope", scope_file=args.scope_file)
            print(f"❌ Error: Cannot write to '{args.scope_file}' (permission denied).")
            sys.exit(1)
        except ValueError as e:
            logger.error("scope_update_value_error", error=str(e))
            print(f"❌ Scope update failed: {e}")
            sys.exit(1)
        except Exception:
            logger.exception("unexpected_scope_update_error", scope_file=args.scope_file, targets_file=args.file)
            print("❌ Unexpected error while updating scope.")
            if args.verbose:
                import traceback

                traceback.print_exc()
            sys.exit(1)

    ScopeValidator.runtime_acknowledgement()
    allowed_targets = ScopeValidator.verify_signed_scope(args.scope_file, secret)
    canonical_allowed = set()
    for allowed in allowed_targets:
        try:
            canonical_allowed.add(parse_and_canonicalize_target(allowed))
        except ValueError:
            logger.warning("invalid_allowed_target_in_scope", target=allowed)

    targets: List[str] = []
    if args.target:
        targets.append(parse_and_canonicalize_target(args.target))
    if args.file:
        targets.extend(
            [
                parse_and_canonicalize_target(line)
                for line in Path(args.file).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        )

    targets = [t for t in targets if t in canonical_allowed]
    if not targets:
        logger.error("no_valid_targets_in_scope")
        sys.exit(1)

    policy = PolicyEngine(args.policy)
    registry = ToolRegistry(policy)
    if args.auto_install:
        remaining_missing = registry.auto_install_missing(args.depth)
        if remaining_missing:
            logger.warning("tools_still_missing_after_auto_install", tools=remaining_missing)

    missing_tools = registry.get_missing_tools(args.depth)
    if missing_tools:
        logger.warning("missing_tools", depth=args.depth, tools=missing_tools)

    db = SQLiteDB(output_dir / "findings.db")
    semaphore = asyncio.Semaphore(args.threads)
    state_machine = RunStateMachine()

    agent = ReconAgentRun(registry, db, semaphore, output_dir, args.retries, state_machine)
    result = await agent.run_recon(targets, args.depth)

    export_results(db, output_dir)
    db.close()

    logger.info("recon_completed", **result)
    print("\n" + "=" * 80)
    print("RECON AGENT COMPLETE")
    print("=" * 80)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("scan_cancelled_by_user")
        sys.exit(130)
    except Exception as e:
        logger.critical("fatal_error", error=str(e))
        sys.exit(1)