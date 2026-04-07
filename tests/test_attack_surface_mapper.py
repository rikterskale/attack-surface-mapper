import asyncio
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

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


class TargetParsingTests(unittest.TestCase):
    def test_parse_target_with_scheme_and_port(self):
        parsed = asm.parse_and_canonicalize_target("https://api.example.com:443/path")
        self.assertEqual(parsed, "api.example.com")

    def test_sanitize_filename_fragment(self):
        cleaned = asm.sanitize_filename_fragment("2001:db8::1")
        self.assertNotIn(":", cleaned)


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