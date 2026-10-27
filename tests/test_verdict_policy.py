"""Synthetic evaluator contracts, not model outcomes or benign-corpus accuracy."""
import json
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from blindsight import diagnostics, reporting, ral
from blindsight.runner.measurement import verdict_policy


class VerdictPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_dir(self, name, verdicts, findings=None, benign=False):
        directory = self.root / name
        directory.mkdir()
        scenario = {"id": "test.case", "sample": "fixture", "variant": "v",
                    "expected_findings": [] if benign else ["persistence"],
                    "label_scope": "exhaustive", "capability_functions": {},
                    "expected_verdict": "benign" if benign else "malicious",
                    "forbidden_verdicts": ["malicious", "suspicious"] if benign else ["benign"]}
        meta = {"run_id": name, "repeats": len(verdicts), "seeds": list(range(len(verdicts))),
                "scenarios_resolved": [scenario],
                "corpus_manifest": {"variants": {"v": {"sha256": "synthetic-test-only"}}}}
        (directory / "meta.json").write_text(json.dumps(meta))
        records = [{"scenario": "test.case", "seed": seed, "calls": [],
                    "trace": {"telemetry": "target_reported"}, "report": {
                    "verdict": verdict, "findings": scenario["expected_findings"] if findings is None else findings}}
                   for seed, verdict in enumerate(verdicts)]
        (directory / "runs.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n")
        return directory

    def edit_policy(self, directory, **values):
        path = directory / "meta.json"
        meta = json.loads(path.read_text())
        meta["scenarios_resolved"][0].update(values)
        path.write_text(json.dumps(meta))

    def test_full_findings_do_not_excuse_a_forbidden_verdict(self):
        card = reporting.scorecard(self.run_dir("bad", ["benign"]))
        self.assertEqual((card["exit_code"], card["rows"][0]["recall"]), (1, 1.0))
        self.assertEqual(card["rows"][0]["forbidden_verdict_runs"], 1)
        self.assertIn("forbidden verdict", " ".join(card["issues"]))

    def test_suspicious_is_not_rejected_when_only_benign_is_forbidden(self):
        card = reporting.scorecard(self.run_dir("allowed", ["suspicious"]))
        self.assertEqual(card["exit_code"], 0)

    def test_verdict_regression_has_paired_seed_and_log_evidence(self):
        base, cand = self.run_dir("base", ["malicious"]), self.run_dir("cand", ["benign"])
        report = diagnostics.release_report(base, cand)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["finding_losses"], [])
        event = report["verdict_regressions"][0]
        self.assertEqual((event["seed"], event["candidate_evidence"]["line"]), (0, 1))
        self.assertEqual((event["baseline_verdict"], event["candidate_verdict"]), ("malicious", "benign"))
        self.assertIn("Verdict regression", diagnostics.html_report(report))

    def test_recovery_elsewhere_cannot_mask_a_new_bad_seed(self):
        report = diagnostics.release_report(self.run_dir("b", ["benign", "malicious"]),
                                            self.run_dir("c", ["malicious", "benign"]))
        row = report["comparison"]["rows"][0]
        self.assertEqual((row["base_verdict_violations"], row["cand_verdict_violations"]), (1, 1))
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual([e["seed"] for e in report["verdict_regressions"]], [1])

    def test_known_bad_baseline_is_visible_but_not_a_new_regression(self):
        base, cand = self.run_dir("b", ["benign"]), self.run_dir("c", ["benign"])
        self.assertEqual(reporting.scorecard(cand)["exit_code"], 1)
        report = diagnostics.release_report(base, cand)
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["comparison"]["rows"][0]["cand_verdict_violations"], 1)

    def test_benign_empty_findings_are_valid_with_recall_not_applicable(self):
        base, cand = self.run_dir("b", ["benign"], benign=True), self.run_dir("c", ["benign"], benign=True)
        card = reporting.scorecard(cand)
        self.assertEqual(card["exit_code"], 0)
        self.assertIsNone(card["rows"][0]["recall"])
        self.assertIn("not applicable", reporting.markdown(card))
        report = diagnostics.release_report(base, cand)
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["comparison"]["unmatched_seeds"], 0)
        self.assertEqual(report["comparison"]["rows"][0]["n"], 1)
        self.assertIn("not applicable", diagnostics.html_report(report))

    def test_legacy_gate_enforces_verdict_without_requiring_recall(self):
        base = self.run_dir("b", ["benign"], benign=True)
        allowed = self.run_dir("allowed", ["benign"], benign=True)
        forbidden = self.run_dir("forbidden", ["malicious"], benign=True)
        args = SimpleNamespace(base=str(base), max_recall_drop=0, max_coverage_drop=0,
                               max_unsupported_increase=0, deny_unauthorized_writes=True,
                               allow_incomplete=False)
        with contextlib.redirect_stdout(io.StringIO()):
            args.candidate = str(allowed)
            self.assertEqual(ral.cmd_gate(args), 0)
            args.candidate = str(forbidden)
            self.assertEqual(ral.cmd_gate(args), 1)

    def test_benign_false_verdict_and_unsupported_finding_are_separate_failures(self):
        base = self.run_dir("b", ["benign"], benign=True)
        for name, verdict, findings in [("false-decision", "malicious", []),
                                         ("false-finding", "benign", ["persistence"])]:
            with self.subTest(name=name):
                cand = self.run_dir(name, [verdict], findings=findings, benign=True)
                self.assertEqual(reporting.scorecard(cand)["exit_code"], 1)
                self.assertEqual(diagnostics.release_report(base, cand)["exit_code"], 1)

    def test_empty_findings_do_not_hide_missing_seeds(self):
        base, cand = self.run_dir("b", ["benign"], benign=True), self.run_dir("c", ["benign"], benign=True)
        for directory in (base, cand):
            path = directory / "meta.json"
            meta = json.loads(path.read_text()); meta.update(seeds=[0, 1], repeats=2)
            path.write_text(json.dumps(meta))
        self.assertEqual(reporting.scorecard(cand)["exit_code"], 2)
        self.assertEqual(diagnostics.release_report(base, cand)["exit_code"], 2)

    def test_policy_changes_are_incompatible_and_do_not_emit_regressions(self):
        base = self.run_dir("b", ["malicious"])
        for name, change in [("policy", {"forbidden_verdicts": ["benign", "suspicious"]}),
                              ("expected", {"expected_verdict": "suspicious"})]:
            with self.subTest(name=name):
                cand = self.run_dir(name, ["malicious"])
                self.edit_policy(cand, **change)
                report = diagnostics.release_report(base, cand)
                self.assertEqual((report["status"], report["exit_code"]), ("INCOMPATIBLE", 2))
                self.assertEqual(report["verdict_regressions"], [])

    def test_policy_order_does_not_create_false_incompatibility(self):
        base, cand = self.run_dir("b", ["benign"], benign=True), self.run_dir("c", ["benign"], benign=True)
        self.edit_policy(cand, forbidden_verdicts=["suspicious", "malicious"])
        self.assertEqual(diagnostics.release_report(base, cand)["exit_code"], 0)

    def test_unconfigured_policy_is_not_reported_as_verified(self):
        directory = self.run_dir("legacy", ["benign"])
        path = directory / "meta.json"
        meta = json.loads(path.read_text()); del meta["scenarios_resolved"][0]["forbidden_verdicts"]
        path.write_text(json.dumps(meta))
        card = reporting.scorecard(directory)
        self.assertIsNone(card["rows"][0]["forbidden_verdict_runs"])
        self.assertIn("not configured", reporting.markdown(card))

    def test_malformed_or_contradictory_policy_is_refused(self):
        for scenario in ({"forbidden_verdicts": "benign"}, {"forbidden_verdicts": ["unknown"]},
                         {"expected_verdict": []}, {"expected_verdict": "benign", "forbidden_verdicts": ["benign"]}):
            with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                verdict_policy(scenario)


if __name__ == "__main__":
    unittest.main()
