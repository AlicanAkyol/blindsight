"""Run with the installed wheel's Python; tests execute outside the repository.

RAL_TEST_BIN=/path/to/venv/bin/ral python tests/test_product.py
The adapter below is simulated test input, never a claimed RE result.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from blindsight import product, reporting

BIN = os.environ.get("RAL_TEST_BIN", str(Path(sys.executable).parent / "ral"))
ADAPTER = (Path(__file__).resolve().parent / "sim_target.py").read_text()


class ProductTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ral-installed-test-")
        self.cwd = Path(self.tmp.name)
        self.adapter = self.cwd / "adapter.py"
        self.adapter.write_text(ADAPTER)

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args):
        return subprocess.run([BIN, *map(str, args)], cwd=self.cwd,
                              text=True, capture_output=True, timeout=60)

    def init_target(self, extra=""):
        command = f'{sys.executable} {self.adapter} {extra}'.strip()
        r = self.cli("init", "--target-command", command)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_assets_validate_outside_repository_without_ghidra(self):
        r = self.cli("validate")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("historical", r.stdout)
        self.assertTrue((self.cwd / ".ral/build/clean/agent_fixture").exists())

    def test_recorded_demo_works_without_config_or_agent(self):
        (self.cwd / ".ral.yaml").write_text("not: [valid yaml")
        result = self.cli("demo")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        root = self.cwd / "blindsight-demo"
        manifest = json.loads((root / "manifest.json").read_text())
        self.assertEqual([r["status"] for r in manifest["results"].values()], ["PASS", "FAIL", "FAIL"])
        self.assertFalse((self.cwd / ".ral").exists())
        report = json.loads((root / "policy-change/release.json").read_text())
        self.assertTrue(any(e["scenario"] == "health.h_neutral" and e["seed"] == 5 and
                            "credential_access" in e["findings"] for e in report["new_unsupported_findings"]))
        reverse = json.loads((root / "coverage-loss/release.json").read_text())
        self.assertTrue(reverse["coverage_losses"])
        self.assertNotIn(str(self.cwd), json.dumps(report))
        for file in (root / "evidence").glob("*/runs.jsonl"):
            self.assertEqual(len(file.read_text().splitlines()), 40)
        self.assertIn("successful-call proxy", (root / "index.html").read_text())
        before = (root / "index.html").read_bytes()
        self.assertEqual(self.cli("demo").returncode, 2)
        self.assertEqual(before, (root / "index.html").read_bytes())

    def test_demo_checksum_failure_creates_no_report(self):
        from unittest.mock import patch
        from blindsight import offline_demo
        output = self.cwd / "bad-demo"
        with patch.dict(offline_demo.HASHES, {f"{offline_demo.NATURAL}/meta.json": "0" * 64}):
            with self.assertRaisesRegex(ValueError, "checksum"):
                offline_demo.render(output)
        self.assertFalse(output.exists())

    def test_init_does_not_overwrite(self):
        self.init_target()
        before = (self.cwd / ".ral.yaml").read_bytes()
        self.assertEqual(self.cli("init").returncode, 2)
        self.assertEqual((self.cwd / ".ral.yaml").read_bytes(), before)

    def test_installed_target_check_reports_baseline_and_gate(self):
        self.init_target()
        r = self.cli("doctor")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.cli("check", "--json", "check.json", "--markdown", "check.md", "--html", "check.html")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        card = json.loads((self.cwd / "check.json").read_text())
        self.assertEqual(card["telemetry"], "target_reported")
        self.assertEqual(len(card["rows"]), 4)
        self.assertTrue((self.cwd / "check.md").exists())
        self.assertTrue((self.cwd / "check.html").exists())
        self.assertEqual(self.cli("baseline", "save").returncode, 0)
        self.assertEqual(self.cli("baseline", "save").returncode, 2)
        r = self.cli("check", "--baseline", "saved")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("GATE PASS", r.stdout)

    def test_check_with_baseline_fails_on_new_unsupported_findings(self):
        self.init_target()
        self.assertEqual(self.cli("check").returncode, 0)
        self.assertEqual(self.cli("baseline", "save").returncode, 0)
        cfg = self.cwd / ".ral.yaml"
        # Same agent, now reporting behaviours that are not in the fixtures.
        cfg.write_text(cfg.read_text().replace("adapter.py", "adapter.py\n    - --extra-findings"))
        r = self.cli("check", "--baseline", "saved")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("GATE FAIL", r.stdout)
        self.assertIn("outside ground truth", r.stdout)

    def test_missing_telemetry_is_not_a_pass(self):
        self.init_target("--no-telemetry")
        r = self.cli("check", "--json", "check.json")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        card = json.loads((self.cwd / "check.json").read_text())
        self.assertTrue(all(row["persistence_coverage"] is None for row in card["rows"]))
        self.assertEqual(self.cli("baseline", "save").returncode, 2)

    def test_capture_case_and_replay_original_controls(self):
        self.init_target()
        self.assertEqual(self.cli("check").returncode, 0)
        r = self.cli("case", "save", "neutral-regression", "--scenario", "agent_fixture.v9_symbol_neutral")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("neutral-regression", self.cli("case", "list").stdout)
        self.assertEqual(self.cli("case", "save", "neutral-regression", "--scenario",
                                  "agent_fixture.v9_symbol_neutral").returncode, 2)
        r = self.cli("check", "--case", "neutral-regression", "--json", "case-report.json")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        card = json.loads((self.cwd / "case-report.json").read_text())
        self.assertEqual({r["scenario"] for r in card["rows"]},
                         {"agent_fixture.clean", "agent_fixture.v9_symbol_neutral"})
        self.assertEqual(card["repeats"], 1)

    def test_compare_writes_release_evidence_files(self):
        self.init_target()
        self.assertEqual(self.cli("check").returncode, 0)
        source = json.loads((self.cwd / ".ral/latest.json").read_text())["run_dir"]
        r = self.cli("compare", source, source, "--json", "release.json", "--html", "release.html")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads((self.cwd / "release.json").read_text())
        self.assertEqual(doc["schema"], "ral.release.v1")
        self.assertEqual(doc["finding_losses"], [])
        self.assertTrue((self.cwd / "release.html").exists())

    def test_malformed_target_is_recorded_as_error(self):
        self.adapter.write_text('print("not json")')
        self.init_target()
        r = self.cli("check", "--json", "check.json")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        card = json.loads((self.cwd / "check.json").read_text())
        self.assertTrue(all(row["errors"] == 1 for row in card["rows"]))

    def test_fixture_hash_tampering_fails(self):
        self.assertEqual(self.cli("validate").returncode, 0)
        (self.cwd / ".ral/build/clean/agent_fixture").write_bytes(b"tampered")
        r = self.cli("validate")
        self.assertEqual(r.returncode, 2)
        self.assertIn("hash mismatch", r.stderr)

    def test_html_escapes_target_controlled_text(self):
        card = {"status": "FINDINGS", "scope": "test", "run_id": "x", "repeats": 1,
                "rows": [], "issues": ['<script>alert("x")</script>'], "actions": [],
                "telemetry": "target_reported", "authority": "unknown"}
        path = self.cwd / "report.html"
        reporting.write_reports(card, html_path=path)
        self.assertNotIn("<script>", path.read_text())
        self.assertIn("&lt;script&gt;", path.read_text())

    def test_external_response_schema_and_timeout(self):
        from blindsight.runner.external import validate_response, run_one
        with self.assertRaises(ValueError):
            validate_response({"protocol":"ral.target.v1", "report":{
                "verdict":"invalid", "findings":[], "summary":"x"}})
        sc = {"id":"t", "task":"triage_readonly"}
        r = run_one({"command":[sys.executable,"-c","import time;time.sleep(5)"],
                     "timeout":0.05}, sc, self.adapter, 0)
        self.assertIn("timed out", r["error"])


if __name__ == "__main__":
    unittest.main()
