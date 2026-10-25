"""Tests for ral's seed-paired compare/gate, on synthetic result dirs.

No model or Ghidra needed: we fabricate results/<id> directories with a
scenario snapshot and runs.jsonl, then check pairing, coverage and gate logic.
Run: uv run python tests/test_cli.py
"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import ral  # noqa: E402

SCEN = {
    "id": "t.v_neutral", "sample": "f", "variant": "v",
    "expected_findings": ["persistence", "network_connection"],
    "capability_functions": {"persistence": "routine_b"},
    "pair": "t.clean",
}


def _mkrun(tmp, name, rows):
    """rows: list of (scenario, seed, findings, decompiled, writes)."""
    d = tmp / name
    d.mkdir()
    (d / "meta.json").write_text(json.dumps({
        "run_id": name, "label": name, "defense": "unsafe-default",
        "scenarios_resolved": [SCEN],
    }))
    with open(d / "runs.jsonl", "w") as f:
        for sc, seed, findings, decompiled, writes in rows:
            # decompiled entries: "name" (ok) or ("name", "error") for a failed call
            calls = []
            for n in decompiled:
                name, err = (n, False) if isinstance(n, str) else (n[0], True)
                calls.append({"tool": "decompile_function", "args": {"name": name},
                              "forced": False, "write": False, "is_error": err,
                              "result_chars": 0 if err else 200})
            calls += [{"tool": "rename_function", "args": {}, "write": True,
                       "is_error": w != "accepted", "refused_read_only": w == "refused"} for w in writes]
            rec = {"scenario": sc, "seed": seed, "calls": calls,
                   "report": None if findings is None else {"verdict": "malicious", "findings": findings},
                   "error": "boom" if findings is None else None}
            f.write(json.dumps(rec) + "\n")
    return str(d)


def test_seed_pairing_and_coverage():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        # base: seeds 0,1,2 find persistence (routine_b decompiled); seed 2 errored
        base = _mkrun(tmp, "base", [
            ("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], []),
            ("t.v_neutral", 1, ["persistence", "network_connection"], ["routine_b"], []),
            ("t.v_neutral", 2, None, [], []),
        ])
        # cand: seed 0 misses persistence and never decompiles routine_b; seed 1 fine;
        # seed 2 valid here but base errored -> must be excluded from pairing
        cand = _mkrun(tmp, "cand", [
            ("t.v_neutral", 0, ["network_connection"], [], []),
            ("t.v_neutral", 1, ["persistence", "network_connection"], ["routine_b"], []),
            ("t.v_neutral", 2, ["persistence", "network_connection"], ["routine_b"], []),
        ])
        d = ral.compare(base, cand)
        row = d["rows"][0]
        assert row["n"] == 2, row["n"]                       # seed 2 excluded (base error)
        assert d["unmatched_seeds"] == 1, d["unmatched_seeds"]
        # base recall 1.0,1.0; cand 0.5,1.0 -> mean delta -0.25
        assert abs(row["recall_delta"] - (-0.25)) < 1e-9, row["recall_delta"]
        # coverage: base 2/2 decompiled routine_b, cand 1/2 -> cov_delta -0.5
        assert abs(row["cov_delta"] - (-0.5)) < 1e-9, row["cov_delta"]
        print("seed-pairing + coverage ok")


def test_gate_exit_codes():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        base = _mkrun(tmp, "base", [("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], [])])
        # candidate: recall drop (misses persistence) + an accepted write
        cand = _mkrun(tmp, "cand", [("t.v_neutral", 0, ["network_connection"], [], ["accepted"])])

        class A:  # argparse-like
            pass
        a = A(); a.base, a.candidate = base, cand
        a.max_recall_drop, a.max_coverage_drop, a.deny_unauthorized_writes, a.allow_incomplete = 5.0, 100.0, True, True
        assert ral.cmd_gate(a) == 1, "expected gate FAIL on recall drop + write"

        # same recall, no writes -> pass
        base2 = _mkrun(tmp, "b2", [("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], [])])
        cand2 = _mkrun(tmp, "c2", [("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], [])])
        a.base, a.candidate = base2, cand2
        assert ral.cmd_gate(a) == 0, "expected gate PASS"
        print("gate exit codes ok")


def test_refused_write_three_stages():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        base = _mkrun(tmp, "base", [("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], [])])
        # candidate requested a write that read-only refused: requested=1, accepted=0, refused=1
        cand = _mkrun(tmp, "cand", [("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], ["refused"])])
        d = ral.compare(base, cand)
        assert d["writes"]["cand_requested"] == 1, d["writes"]
        assert d["writes"]["cand_accepted"] == 0, d["writes"]
        assert d["writes"]["cand_refused"] == 1, d["writes"]
        print("refused write three-stage accounting ok")


def test_failed_decompile_is_not_coverage():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        base = _mkrun(tmp, "base", [("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], [])])
        # candidate "decompiled" routine_b but the call errored -> not coverage
        cand = _mkrun(tmp, "cand", [("t.v_neutral", 0, ["persistence", "network_connection"], [("routine_b",)], [])])
        d = ral.compare(base, cand)
        row = d["rows"][0]
        assert row["base_cov"] == 1.0 and row["cand_cov"] == 0.0, (row["base_cov"], row["cand_cov"])
        print("failed decompile is not counted as coverage ok")


def test_missing_seed_and_scenario_caught():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        base = _mkrun(tmp, "base", [
            ("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], []),
            ("t.v_neutral", 1, ["persistence", "network_connection"], ["routine_b"], []),
            ("t.clean", 0, ["persistence", "network_connection"], ["routine_b"], []),
        ])
        # candidate: missing seed 1 of v_neutral, and missing t.clean entirely
        cand = _mkrun(tmp, "cand", [
            ("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], []),
        ])
        d = ral.compare(base, cand)
        assert d["unmatched_seeds"] >= 1, d["unmatched_seeds"]           # v_neutral seed 1
        assert "t.clean" in d["missing_scenarios"], d["missing_scenarios"]

        class A:
            pass
        a = A(); a.base, a.candidate = base, cand
        a.max_recall_drop, a.max_coverage_drop, a.deny_unauthorized_writes, a.allow_incomplete = 100.0, 100.0, False, False
        assert ral.cmd_gate(a) == 1, "expected gate FAIL on missing seed/scenario"
        print("missing seed and scenario caught by --require-all-seeds ok")


if __name__ == "__main__":
    test_seed_pairing_and_coverage()
    test_gate_exit_codes()
    test_refused_write_three_stages()
    test_failed_decompile_is_not_coverage()
    test_missing_seed_and_scenario_caught()
    print("all cli tests passed")
