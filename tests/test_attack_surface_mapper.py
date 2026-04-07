import asyncio
import hashlib
import hmac
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "attack-surface-mapper.py"
spec = importlib.util.spec_from_file_location("attack_surface_mapper", MODULE_PATH)
asm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asm)


def _make_scope(targets, secret):
    """Helper: build a scope dict with a valid v3.4 canonicalized signature."""
    sig = asm.ScopeValidator._compute_signature(targets, secret)
    canonical = asm._canonicalize_targets(targets)
    return {"allowed_targets": canonical, "signature": sig}


def _write_scope(path, targets, secret):
    """Helper: write a signed scope.json to *path*."""
    data = _make_scope(targets, secret)
    Path(path).write_text(json.dumps(data), encoding="utf-8")
    return data


class ScopeValidatorTests(unittest.TestCase):
    def test_verify_signed_scope_rejects_non_list_targets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            scope.write_text(json.dumps({"allowed_targets": "example.com", "signature": "abc"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                asm.ScopeValidator.verify_signed_scope(str(scope), "secret")

    def test_verify_signed_scope_accepts_valid_signature(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            _write_scope(scope, ["example.com"], "secret123")
            verified = asm.ScopeValidator.verify_signed_scope(str(scope), "secret123")
            self.assertEqual(verified, ["example.com"])

    def test_verify_signed_scope_rejects_wrong_secret(self):
        """Issue #26: verify that a tampered or wrong secret is rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            _write_scope(scope, ["example.com"], "correct-secret")
            with self.assertRaises(ValueError) as ctx:
                asm.ScopeValidator.verify_signed_scope(str(scope), "wrong-secret")
            self.assertIn("Invalid scope signature", str(ctx.exception))

    def test_verify_signed_scope_rejects_tampered_targets(self):
        """Issue #26: verify that adding a target without re-signing is caught."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            data = _make_scope(["example.com"], "secret123")
            # Inject a target without updating the signature
            data["allowed_targets"].append("evil.com")
            Path(scope).write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                asm.ScopeValidator.verify_signed_scope(str(scope), "secret123")

    def test_verify_signed_scope_rejects_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            asm.ScopeValidator.verify_signed_scope("/nonexistent/scope.json", "secret")

    def test_verify_signed_scope_rejects_empty_signature(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            scope.write_text(json.dumps({"allowed_targets": ["example.com"], "signature": "   "}), encoding="utf-8")
            with self.assertRaises(ValueError):
                asm.ScopeValidator.verify_signed_scope(str(scope), "secret")

    def test_canonicalized_signing_accepts_mixed_case(self):
        """v3.4: mixed-case targets should verify because signing canonicalizes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            _write_scope(scope, ["Example.COM", "API.Example.Com"], "secret123")
            verified = asm.ScopeValidator.verify_signed_scope(str(scope), "secret123")
            self.assertEqual(verified, ["api.example.com", "example.com"])


class ScopeUpdateTests(unittest.TestCase):
    """Issue #27: tests for update_and_resign."""

    def test_update_and_resign_creates_new_scope(self):
        """Signing a new scope file from scratch when none exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            asm.ScopeValidator.update_and_resign(str(scope), ["example.com"], "secret123")

            self.assertTrue(scope.exists())
            data = json.loads(scope.read_text(encoding="utf-8"))
            self.assertIn("example.com", data["allowed_targets"])
            self.assertIn("signature", data)

            # Resulting file should verify cleanly
            verified = asm.ScopeValidator.verify_signed_scope(str(scope), "secret123")
            self.assertEqual(verified, ["example.com"])

    def test_update_and_resign_merges_targets(self):
        """New targets are merged with existing, deduplicated, and sorted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            _write_scope(scope, ["alpha.example.com"], "secret123")

            asm.ScopeValidator.update_and_resign(
                str(scope), ["beta.example.com", "alpha.example.com"], "secret123"
            )

            verified = asm.ScopeValidator.verify_signed_scope(str(scope), "secret123")
            self.assertEqual(verified, ["alpha.example.com", "beta.example.com"])

    def test_update_and_resign_canonicalizes(self):
        """Targets with schemes/ports are canonicalized before merging."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            asm.ScopeValidator.update_and_resign(
                str(scope), ["https://Example.com:443/path"], "secret123"
            )
            verified = asm.ScopeValidator.verify_signed_scope(str(scope), "secret123")
            self.assertEqual(verified, ["example.com"])

    def test_update_and_resign_result_verifies(self):
        """Round-trip: update then verify must succeed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            targets = ["10.0.0.1", "example.com", "192.168.1.0/24"]
            asm.ScopeValidator.update_and_resign(str(scope), targets, "my-secret")
            # Must not raise
            verified = asm.ScopeValidator.verify_signed_scope(str(scope), "my-secret")
            self.assertEqual(len(verified), 3)


class PolicyEngineTests(unittest.TestCase):
    """Issue #27: tests for PolicyEngine with custom overrides."""

    def test_default_policy_matches_builtin_tools(self):
        policy = asm.PolicyEngine()
        self.assertTrue(policy.is_tool_allowed("nmap", "standard"))
        self.assertFalse(policy.is_tool_allowed("nmap", "passive"))
        self.assertTrue(policy.is_tool_allowed("nuclei", "deep"))

    def test_custom_policy_overrides_tools(self):
        """A policy file can add tools to a depth level."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.json"
            custom = {
                "allowed_tools": {
                    "passive": ["amass", "subfinder", "custom_tool"],
                    "standard": ["nmap"],
                    "deep": [],
                }
            }
            policy_path.write_text(json.dumps(custom), encoding="utf-8")

            engine = asm.PolicyEngine(str(policy_path))
            self.assertTrue(engine.is_tool_allowed("custom_tool", "passive"))
            self.assertTrue(engine.is_tool_allowed("nmap", "standard"))
            self.assertFalse(engine.is_tool_allowed("nuclei", "deep"))

    def test_malformed_policy_raises(self):
        """v3.4: malformed policy file raises instead of silently falling back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.json"
            policy_path.write_text("not valid json {{{", encoding="utf-8")
            with self.assertRaises(ValueError):
                asm.PolicyEngine(str(policy_path))

    def test_missing_policy_file_uses_defaults(self):
        """A non-existent policy path falls back to built-in defaults."""
        engine = asm.PolicyEngine("/nonexistent/policy.json")
        self.assertTrue(engine.is_tool_allowed("nmap", "standard"))


class AutoInstallTests(unittest.TestCase):
    """Issue #27: tests for auto_install_missing."""

    def test_auto_install_skipped_on_non_kali(self):
        """On non-Kali platforms, returns missing list without calling apt."""
        policy = asm.PolicyEngine()
        registry = asm.ToolRegistry(policy)

        with patch.object(asm, "IS_KALI", False):
            # All tools are likely missing in the test env
            missing_before = registry.get_missing_tools("passive")
            if not missing_before:
                self.skipTest("All passive tools are installed")

            still_missing = registry.auto_install_missing("passive")
            self.assertEqual(set(still_missing), set(missing_before))

    def test_auto_install_calls_apt_on_kali(self):
        """On Kali, apt-get install is called with the right packages."""
        policy = asm.PolicyEngine()
        registry = asm.ToolRegistry(policy)

        # Pretend we're on Kali and only nmap is missing
        with patch.object(asm, "IS_KALI", True), \
             patch.object(asm.shutil, "which") as mock_which, \
             patch.object(asm.subprocess, "run") as mock_run:

            def which_side_effect(cmd):
                if cmd == "apt-get":
                    return "/usr/bin/apt-get"
                if cmd == "nmap":
                    return None  # missing on first call
                return f"/usr/bin/{cmd}"

            mock_which.side_effect = which_side_effect

            registry.auto_install_missing("standard")

            # Verify apt-get install was called
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            self.assertEqual(call_args[0], "/usr/bin/apt-get")
            self.assertEqual(call_args[1], "install")
            self.assertEqual(call_args[2], "-y")

    def test_auto_install_returns_empty_when_nothing_missing(self):
        """When all tools are installed, returns empty list without calling apt."""
        policy = asm.PolicyEngine()
        registry = asm.ToolRegistry(policy)

        # Pretend all tools are installed
        with patch.object(asm.Tool, "is_installed", return_value=True):
            result = registry.auto_install_missing("passive")
            self.assertEqual(result, [])


class TargetParsingTests(unittest.TestCase):
    def test_parse_target_with_scheme_and_port(self):
        parsed = asm.parse_and_canonicalize_target("https://api.example.com:443/path")
        self.assertEqual(parsed, "api.example.com")

    def test_sanitize_filename_fragment(self):
        cleaned = asm.sanitize_filename_fragment("2001:db8::1")
        self.assertNotIn(":", cleaned)

    def test_parse_targets_from_lines_splits_valid_and_invalid(self):
        valid, invalid = asm.parse_targets_from_lines(
            ["https://api.example.com:443/path", "bad target", "10.0.0.1", ""]
        )
        self.assertEqual(valid, ["api.example.com", "10.0.0.1"])
        self.assertEqual(invalid, ["bad target"])

    def test_parse_bare_ip(self):
        self.assertEqual(asm.parse_and_canonicalize_target("10.0.0.1"), "10.0.0.1")

    def test_parse_cidr_strips_prefix(self):
        # The canonicalizer strips path-like suffixes including CIDR prefixes,
        # then the bare IP is validated.  This is existing v3.3 behavior.
        self.assertEqual(asm.parse_and_canonicalize_target("192.168.1.0/24"), "192.168.1.0")

    def test_parse_rejects_garbage(self):
        with self.assertRaises(ValueError):
            asm.parse_and_canonicalize_target("not a valid target!")

    def test_canonicalize_targets_deduplicates_and_sorts(self):
        result = asm._canonicalize_targets(["example.com", "EXAMPLE.COM", "alpha.example.com"])
        self.assertEqual(result, ["alpha.example.com", "example.com"])


class CorrelationTests(unittest.TestCase):
    def test_dedup_then_correlate(self):
        c = asm.CorrelationEngine()
        vuln1 = asm.Finding(tool="nuclei", asset="example.com", indicator="tmpl-1", value="v1", type="vulnerability")
        vuln2 = asm.Finding(tool="nuclei", asset="example.com", indicator="tmpl-2", value="v2", type="vulnerability")
        dup = asm.Finding(tool="nuclei", asset="example.com", indicator="tmpl-2", value="v2-dup", type="vulnerability")
        c.add_finding(vuln1)
        c.add_finding(vuln2)
        c.add_finding(dup)

        unique = c.deduplicate()
        correlated = asm.CorrelationEngine.correlate(unique)

        self.assertEqual(len(unique), 2)
        for finding in correlated:
            self.assertEqual(len(finding.correlated_to), 1)


class ParserTests(unittest.TestCase):
    def test_nuclei_json_parser(self):
        tool = asm.Tool("nuclei", ["nuclei"])
        output = '{"template-id":"xss-test","matched-at":"https://a.example","info":{"severity":"high"}}\n'
        findings = tool._parse_output(output, "example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "vulnerability")
        self.assertEqual(findings[0].severity, "high")

    def test_nmap_xml_parser(self):
        tool = asm.Tool("nmap", ["nmap"])
        output = """<nmaprun><host><address addr='10.0.0.1'/><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https'/></port></ports></host></nmaprun>"""
        findings = tool._parse_output(output, "10.0.0.1")
        self.assertEqual(len(findings), 1)
        self.assertIn("open_tcp_443", findings[0].indicator)

    def test_is_installed_checks_command_name_not_registry_key(self):
        tool = asm.Tool("theharvester", ["theHarvester", "-d", "{target}"])
        with patch.object(asm.shutil, "which", return_value="/usr/bin/theHarvester") as which_mock:
            self.assertTrue(tool.is_installed())
            which_mock.assert_called_once_with("theHarvester")

    def test_subfinder_json_parser(self):
        tool = asm.Tool("subfinder", ["subfinder"])
        output = '{"host":"sub.example.com","input":"example.com"}\n'
        findings = tool._parse_output(output, "example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "subdomain")
        self.assertEqual(findings[0].asset, "sub.example.com")

    def test_httpx_json_parser(self):
        tool = asm.Tool("httpx", ["httpx"])
        output = '{"url":"https://example.com","host":"example.com","status-code":200}\n'
        findings = tool._parse_output(output, "example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "web_service")
        self.assertEqual(findings[0].indicator, "http_200")

    def test_naabu_json_parser(self):
        tool = asm.Tool("naabu", ["naabu"])
        output = '{"host":"10.0.0.1","port":8080}\n'
        findings = tool._parse_output(output, "10.0.0.1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "open_port")
        self.assertEqual(findings[0].indicator, "port_8080")

    def test_generic_line_parser(self):
        tool = asm.Tool("assetfinder", ["assetfinder"])
        output = "sub1.example.com\nsub2.example.com\n"
        findings = tool._parse_output(output, "example.com")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].type, "generic")

    def test_nmap_malformed_xml_falls_back_to_generic(self):
        tool = asm.Tool("nmap", ["nmap"])
        output = "Not XML at all\nsome other line\n"
        findings = tool._parse_output(output, "10.0.0.1")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].type, "generic")

    def test_empty_output_returns_no_findings(self):
        tool = asm.Tool("subfinder", ["subfinder"])
        self.assertEqual(tool._parse_output("", "example.com"), [])
        self.assertEqual(tool._parse_output("   \n  \n", "example.com"), [])

    def test_source_raw_is_populated(self):
        """v3.4: source_raw should be set on all findings."""
        tool = asm.Tool("nuclei", ["nuclei"])
        output = '{"template-id":"test","info":{"severity":"high"}}\n'
        findings = tool._parse_output(output, "example.com")
        self.assertIsNotNone(findings[0].source_raw)


class CLIMainIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_main_exits_on_invalid_cli_target(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            _write_scope(scope, ["example.com"], "secret123")

            args = [
                "attack-surface-mapper.py",
                "bad target",
                "--scope-file", str(scope),
                "--scope-secret", "secret123",
                "--output-dir", str(Path(tmpdir) / "out"),
            ]

            with patch.object(sys, "argv", args), \
                 patch.object(asm.ScopeValidator, "runtime_acknowledgement", return_value=None):
                try:
                    with self.assertRaises(SystemExit) as ctx:
                        await asm.main()
                    self.assertEqual(ctx.exception.code, 1)
                finally:
                    asm._configure_logger()

    async def test_main_exits_on_missing_targets_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Path(tmpdir) / "scope.json"
            _write_scope(scope, ["example.com"], "secret123")

            missing_file = Path(tmpdir) / "does-not-exist.txt"
            args = [
                "attack-surface-mapper.py",
                "--file", str(missing_file),
                "--scope-file", str(scope),
                "--scope-secret", "secret123",
                "--output-dir", str(Path(tmpdir) / "out"),
            ]

            with patch.object(sys, "argv", args), \
                 patch.object(asm.ScopeValidator, "runtime_acknowledgement", return_value=None):
                try:
                    with self.assertRaises(SystemExit) as ctx:
                        await asm.main()
                    self.assertEqual(ctx.exception.code, 1)
                finally:
                    asm._configure_logger()


class ExportTests(unittest.TestCase):
    def test_export_results_writes_jsonl_and_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            db = asm.SQLiteDB(out / "findings.db")

            finding = asm.Finding(
                tool="nmap",
                asset="10.0.0.1",
                indicator="open_tcp_443",
                value="open tcp/443 service=https",
                type="open_port",
            )
            db.add_finding(finding.model_dump())
            db.commit()

            asm.export_results(db, out)
            db.close()

            jsonl = out / "findings.jsonl"
            csvf = out / "findings.csv"

            self.assertTrue(jsonl.exists())
            self.assertTrue(csvf.exists())

            json_lines = jsonl.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(json_lines), 1)

            csv_lines = csvf.read_text(encoding="utf-8").strip().splitlines()
            self.assertGreaterEqual(len(csv_lines), 2)  # header + row
            self.assertIn("open_tcp_443", csv_lines[1])

    def test_source_raw_persisted_to_sqlite(self):
        """v3.4: source_raw column must exist and store data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            db = asm.SQLiteDB(out / "findings.db")

            finding = asm.Finding(
                tool="nuclei",
                asset="example.com",
                indicator="tmpl-1",
                value="v1",
                type="vulnerability",
                source_raw='{"template-id":"tmpl-1"}',
            )
            db.add_finding(finding.model_dump())
            db.commit()

            row = db.conn.execute("SELECT source_raw FROM findings LIMIT 1").fetchone()
            self.assertEqual(row[0], '{"template-id":"tmpl-1"}')
            db.close()


class AsyncRunTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_recon_marks_partial_on_tool_exception(self):
        class BrokenTool:
            async def execute(self, target, semaphore, output_dir, retries=2):
                raise RuntimeError("boom")

        class FakeRegistry:
            def __init__(self):
                self.tools = {"broken": BrokenTool()}

            def get_allowed_tools(self, depth):
                return ["broken"]

        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            db = asm.SQLiteDB(out / "findings.db")
            agent = asm.ReconAgentRun(
                registry=FakeRegistry(),
                db=db,
                semaphore=asyncio.Semaphore(1),
                output_dir=out,
                retries=0,
                state_machine=asm.RunStateMachine(),
            )
            result = await agent.run_recon(["example.com"], "passive")
            db.close()

        self.assertEqual(result["state"], asm.RunState.PARTIAL_SUCCESS.value)
        self.assertTrue(result["errors"])


if __name__ == "__main__":
    unittest.main()
