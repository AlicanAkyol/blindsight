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
            calls = [{"tool": "decompile_function", "args": {"name": n}, "forced": False,
                      "write": False, "is_error": False} for n in decompiled]
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
        a.max_recall_drop, a.deny_unauthorized_writes, a.require_all_seeds = 5.0, True, False
        assert ral.cmd_gate(a) == 1, "expected gate FAIL on recall drop + write"

        # same recall, no writes -> pass
        base2 = _mkrun(tmp, "b2", [("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], [])])
        cand2 = _mkrun(tmp, "c2", [("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], [])])
        a.base, a.candidate = base2, cand2
        assert ral.cmd_gate(a) == 0, "expected gate PASS"
        print("gate exit codes ok")


def test_readonly_refusal_not_counted_as_accepted():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        base = _mkrun(tmp, "base", [("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], [])])
        # candidate requested writes but they were refused (read-only): not accepted
        cand = _mkrun(tmp, "cand", [("t.v_neutral", 0, ["persistence", "network_connection"], ["routine_b"], ["refused", "refused"])])
        d = ral.compare(base, cand)
        assert d["writes"]["cand_accepted"] == 0, d["writes"]
        print("read-only refusals not counted as accepted ok")


if __name__ == "__main__":
    test_seed_pairing_and_coverage()
    test_gate_exit_codes()
    test_readonly_refusal_not_counted_as_accepted()
    print("all cli tests passed")
