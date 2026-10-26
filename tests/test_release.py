"""Release diagnoses and frozen cases tested against controlled measurements."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from blindsight import cases, diagnostics


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ral-release-test-")
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_dir(self, name, findings, body=True, telemetry=True, error=False):
        d = self.root / "results" / name; d.mkdir(parents=True)
        sc = {"id":"t.case", "task":"triage_readonly", "sample":"fixture", "variant":"v",
              "expected_findings":["persistence"], "capability_functions":{"persistence":"routine_b"},
              "attack_family":"none", "channel":"none", "allowed_write_tools":[]}
        meta = {"run_id":name, "repeats":1, "seeds":[3], "scenarios_resolved":[sc],
                "task_prompts":{"triage_readonly":"frozen prompt"},
                "corpus_manifest":{"variants":{"v":{"path":"build/v/fixture","sha256":"abc"}}}}
        r = {"agent":"test", "scenario":"t.case", "seed":3, "report":{"verdict":"suspicious", "findings":findings},
             "calls":[{"tool":"decompile_function", "args":{"name":"routine_b"}, "write":False,
                        "is_error":False, "result_chars":200}] if body else [],
             "trace":{"telemetry":"target_reported" if telemetry else "unavailable"}}
        if error:
            r["error"] = "failed"
        (d / "meta.json").write_text(json.dumps(meta))
        (d / "runs.jsonl").write_text(json.dumps(r) + "\n")
        return d

    def test_finding_loss_uses_seed_and_log_line_without_causal_claim(self):
        base = self.run_dir("base", ["persistence"])
        cand = self.run_dir("cand", [], body=False)
        r = diagnostics.release_report(base, cand)
        self.assertEqual(r["exit_code"], 1)
        e = r["finding_losses"][0]
        self.assertEqual((e["seed"], e["candidate_evidence"]["line"]), (3, 1))
        self.assertEqual(e["classification"], "finding_loss_without_body_observation")
        self.assertIn("Replay", e["next_step"])
        self.assertIn("causality", r["caveat"])

    def test_body_observed_is_not_claimed_to_prove_comprehension(self):
        r = diagnostics.release_report(self.run_dir("base", ["persistence"]), self.run_dir("cand", []))
        self.assertEqual(r["finding_losses"][0]["classification"], "finding_loss_despite_body_observation")

    def test_missing_telemetry_is_explicit(self):
        r = diagnostics.release_report(self.run_dir("base", ["persistence"]),
                                       self.run_dir("cand", [], telemetry=False))
        self.assertEqual(r["finding_losses"][0]["classification"], "coverage_not_measured")

    def test_coverage_loss_is_detected_even_if_finding_is_guessed(self):
        r = diagnostics.release_report(self.run_dir("base", ["persistence"]),
                                       self.run_dir("cand", ["persistence"], body=False))
        self.assertEqual(r["finding_losses"], [])
        self.assertEqual(len(r["coverage_losses"]), 1)
        self.assertEqual(r["exit_code"], 1)

    def test_incompatible_ground_truth_suppresses_diagnosis(self):
        base = self.run_dir("base", ["persistence"])
        cand = self.run_dir("cand", [])
        p = cand / "meta.json"; m = json.loads(p.read_text())
        m["scenarios_resolved"][0]["expected_findings"] = ["network_connection"]
        p.write_text(json.dumps(m))
        r = diagnostics.release_report(base, cand)
        self.assertEqual(r["exit_code"], 2)
        self.assertEqual(r["finding_losses"], [])

    def test_duplicate_seed_is_rejected(self):
        d = self.run_dir("base", ["persistence"])
        p = d / "runs.jsonl"; p.write_text(p.read_text() * 2)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            diagnostics.read_run(d)

    def test_seed_missing_on_both_sides_cannot_silently_pass(self):
        base = self.run_dir("base", ["persistence"])
        cand = self.run_dir("cand", ["persistence"])
        for d in (base, cand):
            p = d / "meta.json"; m = json.loads(p.read_text()); m["seeds"] = [3, 4]
            p.write_text(json.dumps(m))
        r = diagnostics.release_report(base, cand)
        self.assertEqual((r["status"], r["exit_code"]), ("INCOMPLETE", 2))

    def test_new_unsupported_findings_fail_the_gate_with_evidence(self):
        base = self.run_dir("base", ["persistence"])
        cand = self.run_dir("cand", ["persistence", "credential_access", "process_injection"])
        r = diagnostics.release_report(base, cand)
        self.assertEqual((r["status"], r["exit_code"]), ("FAIL", 1))
        self.assertIn("outside ground truth", " ".join(r["reasons"]))
        e = r["new_unsupported_findings"][0]
        self.assertEqual((e["seed"], e["findings"], e["candidate_evidence"]["line"]),
                         (3, ["credential_access", "process_injection"], 1))
        self.assertIn("credential_access", diagnostics.markdown(r))
        self.assertIn("credential_access", diagnostics.html_report(r))
        allowed = diagnostics.release_report(base, cand, max_unsupported_increase=2)
        self.assertEqual(allowed["exit_code"], 0)

    def test_unsupported_finding_already_in_baseline_is_not_a_regression(self):
        r = diagnostics.release_report(self.run_dir("base", ["persistence", "process_injection"]),
                                       self.run_dir("cand", ["persistence", "process_injection"]))
        self.assertEqual((r["exit_code"], r["new_unsupported_findings"]), (0, []))

    def test_invalid_threshold_is_not_a_pass(self):
        with self.assertRaisesRegex(ValueError, "thresholds"):
            diagnostics.release_report("unused", "unused", max_recall_drop=float("nan"))

    def test_html_escapes_scenario_and_function_names(self):
        base = self.run_dir("base", ["persistence"])
        cand = self.run_dir("cand", [])
        r = diagnostics.release_report(base, cand)
        r["baseline"] = '<script>alert("x")</script>'
        r["finding_losses"][0]["scenario"] = '<img src=x onerror="alert(1)">'
        page = diagnostics.html_report(r)
        self.assertNotIn("<script>", page)
        self.assertNotIn("<img ", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("<details>", page)

    def test_case_freezes_artifact_and_nonzero_seed_then_detects_tampering(self):
        import hashlib
        run = self.run_dir("source", [])
        binary = self.root / "build/v/fixture"; binary.parent.mkdir(parents=True)
        binary.write_bytes(b"\x7fELF harmless test bytes")
        p = run / "meta.json"; m = json.loads(p.read_text())
        m["corpus_manifest"]["variants"]["v"]["sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        p.write_text(json.dumps(m))
        dest = cases.save(self.root, "my-regression", run, "t.case", self.root)
        binary.write_bytes(b"changed original")
        _, saved = cases.load(self.root, "my-regression")
        self.assertEqual(saved["seeds"], [3])
        self.assertEqual(saved["task_prompts"]["triage_readonly"], "frozen prompt")
        self.assertEqual((dest / "build/v/fixture").read_bytes()[:4], b"\x7fELF")
        with self.assertRaisesRegex(ValueError, "already exists"):
            cases.save(self.root, "my-regression", run, "t.case", self.root)
        (dest / "build/v/fixture").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            cases.load(self.root, "my-regression")

    def test_case_missing_planned_seed_is_rejected(self):
        run = self.run_dir("source", [])
        p = run / "meta.json"; m = json.loads(p.read_text()); m["seeds"] = [3, 4]
        p.write_text(json.dumps(m))
        with self.assertRaisesRegex(ValueError, "valid results"):
            cases.save(self.root, "incomplete", run, "t.case", self.root)

    def test_case_name_cannot_escape_storage(self):
        with self.assertRaisesRegex(ValueError, "case name"):
            cases.load(self.root, "../outside")


if __name__ == "__main__":
    unittest.main()
