import asyncio
import hashlib
import hmac
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "attack-surface-mapper.py"
spec = importlib.util.spec_from_file_location("attack_surface_mapper", MODULE_PATH)
asm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asm)


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
            targets = ["example.com"]
            payload = json.dumps({"allowed_targets": targets}, sort_keys=True).encode()
            signature = hmac.new(b"secret123", payload, hashlib.sha256).hexdigest()
            scope.write_text(json.dumps({"allowed_targets": targets, "signature": signature}), encoding="utf-8")
            verified = asm.ScopeValidator.verify_signed_scope(str(scope), "secret123")
            self.assertEqual(verified, targets)


class TargetParsingTests(unittest.TestCase):
    def test_parse_target_with_scheme_and_port(self):
        parsed = asm.parse_and_canonicalize_target("https://api.example.com:443/path")
        self.assertEqual(parsed, "api.example.com")

    def test_sanitize_filename_fragment(self):
        cleaned = asm.sanitize_filename_fragment("2001:db8::1")
        self.assertNotIn(":", cleaned)


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